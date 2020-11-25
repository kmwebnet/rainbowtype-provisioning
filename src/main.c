/*
MIT License

Copyright (c) 2020 kmwebnet

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* System Includes */
#include <stdio.h>
#include "stdlib.h"
#include <string.h>
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "driver/uart.h"
#include "soc/uart_struct.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_event_loop.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "sdkconfig.h" // generated by "make menuconfig"


/* From Cryptoauthlib */
#include "cryptoauthlib.h"
#include "atcacert/atcacert_pem.h"
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_def.h"
#include "mbedtls/atca_mbedtls_wrap.h"

#include "provision.h"



#define EX_UART_NUM UART_NUM_0
#define PATTERN_CHR_NUM    (3) 

#define BUF_SIZE (2048)
#define RD_BUF_SIZE (BUF_SIZE)
static QueueHandle_t uart0_queue;



#define SDA2_PIN GPIO_NUM_18
#define SCL2_PIN GPIO_NUM_19

#define TAG "MAIN"

#define I2C_MASTER_ACK 0
#define I2C_MASTER_NACK 1

ATCAIfaceCfg cfg;

#define PEM_PK_BEGIN "-----BEGIN PUBLIC KEY-----"
#define PEM_PK_END   "-----END PUBLIC KEY-----"

const char certificatefooter[] = "----END CERTIFICATE----";
const char pubkeyfooter[] = "----END PUBLIC KEY----";

uint8_t stateflag = 0;
uint16_t certificateoffset = 0;


char signercert[1000] = {};
char devicecert[1000] = {};
char rootpubkey[200] = {};

char serialstr[20] = {};

uint8_t provisioning_signer_cert[500] = {};
uint8_t provisioning_device_cert[500] = {};
uint8_t provisioning_root_public_key[100] = {};

char topicname[64];
char datacontents[1000];


void i2c_master_init()
{
	i2c_config_t i2c_config = {
		.mode = I2C_MODE_MASTER,
		.sda_io_num = SDA2_PIN,
		.scl_io_num = SCL2_PIN,
		.sda_pullup_en = GPIO_PULLUP_DISABLE,
		.scl_pullup_en = GPIO_PULLUP_DISABLE,
		.master.clk_speed = 100000
		};
			
	i2c_param_config(I2C_NUM_0 , &i2c_config);
	i2c_driver_install(I2C_NUM_0 , I2C_MODE_MASTER, 0, 0, 0);


}

void get_atecc608cfg(ATCAIfaceCfg *cfg)
{
                cfg->iface_type             = ATCA_I2C_IFACE;
                cfg->devtype                = ATECC608A;
                cfg->atcai2c.slave_address  = 0XC0;
                cfg->atcai2c.bus            = 1;
                cfg->atcai2c.baud           = 100000;
                cfg->wake_delay             = 1500;
                cfg->rx_retries             = 20;

return;
}

int atca_configure(uint8_t i2c_addr , ATCAIfaceCfg *cfg);
int createkeys(uint8_t i2c_addr, ATCAIfaceCfg *cfg);



static void uart_event_task(void *pvParameters)
{
    uart_event_t event;
    size_t buffered_size;
    uint8_t* dtmp = (uint8_t*) malloc(RD_BUF_SIZE);
    for(;;) {
        //Waiting for UART event.
        if(xQueueReceive(uart0_queue, (void * )&event, (portTickType)portMAX_DELAY)) {
            bzero(dtmp, RD_BUF_SIZE);
            switch(event.type) {
                //Event of UART receving data
                /*We'd better handler data event fast, there would be much more data events than
                other types of events. If we take too much time on data event, the queue might
                be full.*/
                case UART_DATA:
                    uart_read_bytes(EX_UART_NUM, dtmp, event.size, portMAX_DELAY);

                    if(stateflag == 1){
                        memcpy (&signercert[certificateoffset], dtmp, event.size);                       
                        certificateoffset += event.size;
                    // detect the end of certificate
                        if ( strstr ((char *)dtmp , certificatefooter) != NULL )
                            {
                                stateflag = 0;
                                certificateoffset = 0;

                                uart_flush(EX_UART_NUM);
                                break;
                            }
                    uart_flush(EX_UART_NUM);
                    break;
                      }

                    if(stateflag == 2){
                        memcpy (&devicecert[certificateoffset], dtmp, event.size);                       
                        certificateoffset += event.size;
                    // detect the end of certificate
                        if ( strstr ((char *)dtmp , certificatefooter) != NULL )
                            {
                                stateflag = 0;
                                certificateoffset = 0;

                                uart_flush(EX_UART_NUM);
                                break;
                            }
                    uart_flush(EX_UART_NUM);
                    break;
                      }

                    if(stateflag == 3){
                        memcpy (&rootpubkey[certificateoffset], dtmp, event.size);                       
                        certificateoffset += event.size;
                    // detect the end of certificate
                        if ( strstr ((char *)dtmp , pubkeyfooter) != NULL )
                            {
                                stateflag = 0;
                                certificateoffset = 0;

                                uart_flush(EX_UART_NUM);
                                break;
                            }
                    uart_flush(EX_UART_NUM);
                    break;
                      }

                    if('r' == dtmp[0]){
                    atca_configure(0xc0, &cfg);
                    printf("Ready.\n");
                    uart_flush(EX_UART_NUM);
                      }

                    if('k' == dtmp[0]){
                    createkeys(0xc0, &cfg);
                    uart_flush(EX_UART_NUM);
                      }

// signer certificate accept mode
                    if('c' == dtmp[0]){
                    stateflag = 1;
                    uart_flush(EX_UART_NUM);
                      }

// device certificate accept mode
                    if('v' == dtmp[0]){
                    stateflag = 2;
                    uart_flush(EX_UART_NUM);
                      }

// root pubkey accept mode
                    if('b' == dtmp[0]){
                    stateflag = 3;
                    uart_flush(EX_UART_NUM);
                      }

                    if('s' == dtmp[0]){
                    uart_write_bytes(EX_UART_NUM, (const char*) serialstr, 18);
                    uart_flush(EX_UART_NUM);
                      }


                    if('p' == dtmp[0]){
                        char printresult[100] = {};
                        for (int i=0 ; i < strlen((const char *)signercert) / 65 + 1  ; i++)
                            {
                                memcpy (printresult, &signercert[i * 65], 65);
                                uart_write_bytes(EX_UART_NUM, (const char*) printresult, 65);
                            }

                    uart_flush(EX_UART_NUM);

                        memset(&printresult, 0 , 100 );
                        for (int i=0 ; i < strlen((const char *)devicecert) / 65 + 1 ; i++)
                            {
                                memcpy (printresult, &devicecert[i * 65], 65);
                                uart_write_bytes(EX_UART_NUM, (const char*) printresult, 65);
                            }
                    uart_flush(EX_UART_NUM);
                    break;
                    }

                    if('o' == dtmp[0]){
                        char printresult[100] = {};
                        for (int i=0 ; i < strlen((const char *)rootpubkey) / 65 + 1 ; i++)
                            {
                                memcpy (printresult, &rootpubkey[i * 65], 65);
                                uart_write_bytes(EX_UART_NUM, (const char*) printresult, 65);
                            }
                    uart_flush(EX_UART_NUM);
                    break;
                      }

                    if('q' == dtmp[0]){
                        stateflag = 10;
                        free(dtmp);
                        dtmp = NULL;
                        uart_flush(EX_UART_NUM);
                        vTaskDelete(NULL);
                      }


                    break;
                //Event of HW FIFO overflow detected
                case UART_FIFO_OVF:
                    ESP_LOGI(TAG, "hw fifo overflow");
                    // If fifo overflow happened, you should consider adding flow control for your application.
                    // The ISR has already reset the rx FIFO,
                    // As an example, we directly flush the rx buffer here in order to read more data.
                    uart_flush_input(EX_UART_NUM);
                    xQueueReset(uart0_queue);
                    break;
                //Event of UART ring buffer full
                case UART_BUFFER_FULL:
                    ESP_LOGI(TAG, "ring buffer full");
                    // If buffer full happened, you should consider encreasing your buffer size
                    // As an example, we directly flush the rx buffer here in order to read more data.
                    uart_flush_input(EX_UART_NUM);
                    xQueueReset(uart0_queue);
                    break;
                //Event of UART RX break detected
                case UART_BREAK:
                    ESP_LOGI(TAG, "uart rx break");
                    break;
                //Event of UART parity check error
                case UART_PARITY_ERR:
                    ESP_LOGI(TAG, "uart parity error");
                    break;
                //Event of UART frame error
                case UART_FRAME_ERR:
                    ESP_LOGI(TAG, "uart frame error");
                    break;
                //UART_PATTERN_DET
                case UART_PATTERN_DET:
                    uart_get_buffered_data_len(EX_UART_NUM, &buffered_size);
                    int pos = uart_pattern_pop_pos(EX_UART_NUM);
                    ESP_LOGI(TAG, "[UART PATTERN DETECTED] pos: %d, buffered size: %d", pos, buffered_size);
                    if (pos == -1) {
                        // There used to be a UART_PATTERN_DET event, but the pattern position queue is full so that it can not
                        // record the position. We should set a larger queue size.
                        // As an example, we directly flush the rx buffer here.
                        uart_flush_input(EX_UART_NUM);
                    } else {
                        uart_read_bytes(EX_UART_NUM, dtmp, pos, 100 / portTICK_PERIOD_MS);
                        uint8_t pat[PATTERN_CHR_NUM + 1];
                        memset(pat, 0, sizeof(pat));
                        uart_read_bytes(EX_UART_NUM, pat, PATTERN_CHR_NUM, 100 / portTICK_PERIOD_MS);
                        ESP_LOGI(TAG, "read data: %s", dtmp);
                        ESP_LOGI(TAG, "read pat : %s", pat);
                    }
                    break;
                //Others
                default:
                    ESP_LOGI(TAG, "uart event type: %d", event.type);
                    break;
            }
        }
    }
    free(dtmp);
    dtmp = NULL;
    vTaskDelete(NULL);
}


        
void doprovisioning (void)
{        
        printf ("\nprovisioning start\n");

// conversion pem format to der

            size_t derbuffer = sizeof(provisioning_signer_cert);
            if (ATCA_SUCCESS != atcacert_decode_pem(signercert, strlen(signercert) , provisioning_signer_cert , &derbuffer , PEM_CERT_BEGIN, PEM_CERT_END )) {
	        printf("signer cert conversion failed" );
            }

            derbuffer = sizeof(provisioning_device_cert);
            if (ATCA_SUCCESS != atcacert_decode_pem(devicecert, strlen(devicecert) , provisioning_device_cert , &derbuffer , PEM_CERT_BEGIN, PEM_CERT_END )) {
	        printf("device cert conversion failed");
            }

            derbuffer = sizeof(provisioning_root_public_key);
            if (ATCA_SUCCESS != atcacert_decode_pem(rootpubkey, strlen(rootpubkey) , provisioning_root_public_key , &derbuffer , PEM_PK_BEGIN, PEM_PK_END )) {
	        printf("root pubkey conversion failed");
            }

        atca_provision(&cfg);


return;
}



void provisioningtask(void)
{

    get_atecc608cfg(&cfg);
    ATCA_STATUS status = atcab_init(&cfg);

    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_init() failed with ret=0x%08d\r\n", status);
    }
	
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    status = atcab_read_serial_number(serial);

    if (status != ATCA_SUCCESS) {
	ESP_LOGE(TAG, "atcab_read_serial_number() failed with ret=0x%08d/r/n", status);
    }

    uint8_t config_data[ATCA_ECC_CONFIG_SIZE];
    status = atcab_read_config_zone(config_data);

    if (status != ATCA_SUCCESS) {
	ESP_LOGE(TAG, "atcab_read_config_zone() failed with ret=0x%08d/r/n", status);
    }

    char character[2] = {};

    for ( int i = 0; i< 9; i++)
        {
        sprintf(character , "%02x", serial[i]);
	    strcat(serialstr, character);
        }

	ESP_LOGI(TAG, "Config Zone data:");

        for (int i = 0; i < 16; i++){
           for(int j = 0; j < 8; j++){
	     printf("%02x ", config_data[i * 8 + j]);
           }
	   printf("\n");
        }

    uart_config_t uart_config = {
       .baud_rate = 115200,
       .data_bits = UART_DATA_8_BITS,
       .parity = UART_PARITY_DISABLE,
       .stop_bits = UART_STOP_BITS_1,
       .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
       //.rx_flow_ctrl_thresh = 122,
       .rx_flow_ctrl_thresh = 0,
    };
    //Set UART parameters
    uart_param_config(EX_UART_NUM, &uart_config);
    //Set UART log level
    esp_log_level_set(TAG, ESP_LOG_INFO);
    //Install UART driver, and get the queue.
    uart_driver_install(EX_UART_NUM, BUF_SIZE * 2, BUF_SIZE * 2, 10, &uart0_queue, 0);

    //Set UART pins (using UART0 default pins ie no changes.)
    uart_set_pin(EX_UART_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    //Set uart pattern detect function.
    uart_enable_pattern_det_intr(EX_UART_NUM, '+', 3, 10000, 10, 10);
    //Reset the pattern queue length to record at most 20 pattern positions.
    uart_pattern_queue_reset(EX_UART_NUM, 20);
    //Create a task to handler UART event from ISR
    xTaskCreate(uart_event_task, "uart_event_task", 2048, NULL, 12, NULL);


    do {

vTaskDelay(100/portTICK_PERIOD_MS); 

    if (stateflag == 10)
    {
    doprovisioning();
    stateflag = 11;

    break;
    }
    

    } while(1);

return;
}


void app_main(void)
{
	i2c_master_init();
    provisioningtask();

}
