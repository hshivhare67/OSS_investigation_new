/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <pthread.h>
#include <utils/Log.h>

// RICOH ADD-S G2 Porting
#include <stdlib.h>
#include <string.h>
// RICOH ADD-E G2 Porting

#include <libnfc_tf_if.h>

// RICOH ADD-S for NFC Error Recovery
#include <time.h>
// RICOH ADD-E for NFC Error Recovery

#include "libnfc_tf.h"
#include "libnfc_tf_local.h"

enum {
	NFC_TF_POLL_STATE_INIT = 0,
	NFC_TF_POLL_STATE_POLLING,
	NFC_TF_POLL_STATE_HOLDING,
	NFC_TF_POLL_STATE_HANDLED,
	NFC_TF_POLL_STATE_HANDLED_P2P_POLLING,
};

#define NFC_TF_DEBUG 1

#define NFC_TF_POLLING_LOOP_SLEEP_USEC		100000  // 100msec
#define NFC_TF_POLLING_LOOP_LOG_USEC		(5*1000*1000)  // 5sec
#define NFC_TF_POLLING_TIMEOUT_VALUE		1024
#define NFC_TF_RESET_COUNT					100

// RICOH ADD-S for NFC Error Recovery
#define NFC_TF_ERROR_RESET_TIMEOUT_VALUE	8  // 8sec
// RICOH ADD-E for NFC Error Recovery

typedef struct {
	libnfc_tf_nfc_detect_callback_t detect_cb;
	libnfc_tf_nfc_taglost_callback_t lost_cb;
	libnfc_tf_nfc_reset_callback_t reset_cb;
} libnfc_tf_callback_t;

static int glibnfc_tf_poll_run = 0;
static int glibnfc_tf_poll_state = NFC_TF_POLL_STATE_INIT;
static int glibnfc_tf_poll_reset_cnt = NFC_TF_RESET_COUNT;

void libnfc_tf_set_poll_state(const char *tag, int state) {
	if (glibnfc_tf_poll_state != state) {
		ALOGI("[%s]polling state change [%d] >> [%d]", tag, glibnfc_tf_poll_state, state);
	}
	glibnfc_tf_poll_state = state;
}

static libnfc_tf_SendCmd_t 		gNfcPollCmdBuf;
static libnfc_tf_FindMediaConfig_t	gNfcFindMediaConf;
static pthread_mutex_t gNfcPollMutex = PTHREAD_MUTEX_INITIALIZER;

static libnfc_tf_callback_t gNfcCallback;
// RICOH ADD-S Felica Security Access
static libnfc_tf_SystemCodeConfig_t	gNfcSystemCodeConf;
// RICOH ADD-E Felica Security Access

// RICOH ADD-S NDEF Detection Settings
static int glibnfc_tf_ndef_detection_settings = NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_ENABLE;
// RICOH ADD-E NDEF Detection Settings

static void libnfc_tf_set_findmedia_command( libnfc_tf_SendCmd_t *tf_cmd, libnfc_tf_FindMediaConfig_t *cfg )
{
	uint8_t *buf;

	buf = &tf_cmd->s_buffer[0];

	libnfc_tf_set_com_header( buf, NFC_TF_CMD_COM_FINDMEDIA, 0x0011 );
	
	buf = &tf_cmd->s_buffer[NFC_TF_CMD_HEADER_LENGTH];

	*buf = cfg->holding;
	buf++;
	*buf = cfg->retry_limit;
	buf++;
	// RICOH MOD-S Felica Security Access, NDEF Detection Settings
	int felica_bit = cfg->felica_setbit;
	if( gNfcSystemCodeConf.felica_systemcode_search == NFC_TF_FELICA_SYSTEM_CODE_ENABLE ){
		// システムコードによるメディア捜査が有効の場合は、bit2をONする
		felica_bit = felica_bit | NFC_TF_SYSTEM_CODE_ENABLE;
	}
	if ( glibnfc_tf_ndef_detection_settings == NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE ){
		// NDEF検知設定が無効な場合は、bit3をONする
		felica_bit = felica_bit | NFC_TF_FINDMEDIA_PARAM_FELICA_BIT_NDEF_DETECTION_DISABLE;
	}
	*buf = felica_bit;
	// RICOH MOD-E Felica Security Access, NDEF Detection Settings
	buf++;

	*buf = cfg->felica_baudrate;
	buf++;
	*buf = cfg->felica_limit;
	buf++;
	// RICOH MOD-S Felica Security Access
	if( gNfcSystemCodeConf.felica_systemcode_search == NFC_TF_FELICA_SYSTEM_CODE_ENABLE ){
		// システムコードによるメディア捜査が有効の場合は、指定されたシステムコードを設定する
		*buf = gNfcSystemCodeConf.felica_systemcode[0];
		buf++;
		*buf = gNfcSystemCodeConf.felica_systemcode[1];
		buf++;
	} else {
		*buf = cfg->felica_systemcode[0];
		buf++;
		*buf = cfg->felica_systemcode[1];
		buf++;
	}
	// RICOH MOD-E Felica Security Access

	// RICOH MOD-S NDEF Detection Settings
	int iso14443a_bit = cfg->iso14443a_setbit;
	if ( glibnfc_tf_ndef_detection_settings == NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE ){
		iso14443a_bit = iso14443a_bit | NFC_TF_FINDMEDIA_PARAM_14443A_BIT_NDEF_DETECTION_DISABLE;
	}
	*buf = iso14443a_bit;
	// RICOH MOD-E NDEF Detection Settings

	buf++;
	*buf = cfg->iso14443a_limit;
	buf++;

	// RICOH MOD-S NDEF Detection Settings
	int iso14443b_bit = cfg->iso14443b_setbit;
	if ( glibnfc_tf_ndef_detection_settings == NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE ){
		iso14443b_bit = iso14443b_bit | NFC_TF_FINDMEDIA_PARAM_14443B_BIT_NDEF_DETECTION_DISABLE;
	}
	*buf = iso14443b_bit;
	buf++;
	// RICOH MOD-E NDEF Detection Settings

	*buf = cfg->iso14443b_limit;
	buf++;
	*buf = cfg->iso14443b_afi;
	buf++;
	*buf = cfg->iso15693_setbit;
	buf++;
	*buf = cfg->iso15693_limit;
	buf++;
	*buf = cfg->iso15693_afi;
	buf++;
	*buf = cfg->p2p_setbit;
	buf++;
	*buf = cfg->p2p_limit;
	buf++;

	libnfc_tf_insert_bcc( tf_cmd->s_buffer, NFC_TF_CMD_HEADER_LENGTH + 0x11 );
	tf_cmd->s_length = NFC_TF_CMD_HEADER_LENGTH + 0x12;
}

static int libnfc_tf_poll_free_media( void )
{
	ALOGI( "%s", __FUNCTION__ );
	int ret;

	memset( &gNfcPollCmdBuf, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &gNfcPollCmdBuf, NFC_TF_CMD_COM_FREEMEDIA, NULL, 0 );
	ret = libnfc_tf_send_command( &gNfcPollCmdBuf );
	return ret;
}

void libnfc_tf_poll_register_detect_callback(libnfc_tf_nfc_detect_callback_t cb_addr)
{
	gNfcCallback.detect_cb = cb_addr;
}

void libnfc_tf_poll_register_taglost_callback(libnfc_tf_nfc_taglost_callback_t cb_addr)
{
	gNfcCallback.lost_cb = cb_addr;
}

void libnfc_tf_poll_register_reset_callback(libnfc_tf_nfc_reset_callback_t cb_addr)
{
	gNfcCallback.reset_cb = cb_addr;
}

void libnfc_tf_poll_stop( void )
{
	glibnfc_tf_poll_run = 0;
}

void libnfc_tf_set_default_findmedia_config( void )
{
	pthread_mutex_lock( &gNfcPollMutex );

        memset( &gNfcFindMediaConf, 0, sizeof(libnfc_tf_FindMediaConfig_t) );
        /* media holding */
        gNfcFindMediaConf.holding = 0x1;
        /* retry default */
        gNfcFindMediaConf.retry_limit = 0xff;

	pthread_mutex_unlock( &gNfcPollMutex );
}

void libnfc_tf_set_findmedia_config( libnfc_tf_FindMediaConfig_t *config )
{
	pthread_mutex_lock( &gNfcPollMutex );

	memcpy( &gNfcFindMediaConf, config, sizeof( libnfc_tf_FindMediaConfig_t ) );

	pthread_mutex_unlock( &gNfcPollMutex );
}

void* libnfc_tf_poll_thread( void *arg )
{
	int ret;
	int query;
	int tag_lost = 0;
	libnfc_tf_detect_data_raw_t detect_data;
	int val;
	int timeout = NFC_TF_POLLING_TIMEOUT_VALUE;
	int log_cnt = NFC_TF_POLLING_LOOP_LOG_USEC;
	struct timeval t_val;
	
	// RICOH ADD-S for NFC Error Recovery
	long poll_error_detected_first_time = -1;
	long poll_error_detected_last_time = -1;
	// RICOH ADD-E for NFC Error Recovery

// RICOH ADD-S G2 Porting  暫定修正
//    現在のポーリングは、ステータス問い合わせに対してHANDLEDを返すことがある
//    HANDLED状態でカードがはずされても状態はHANDLEDを維持してしまい、カードがはずれたことを検出できない
//    ここでは10回(3.5秒)HANDLEDが連続すると、カードが外れた処理を行う。
        int holdingCount = 0;
// RICOH ADD-E G2 Porting  暫定修正

	if ( arg != NULL ){
		val = *((int*)arg);
	}

	pthread_setname_np(pthread_self(), "NFC TF Thread");

	glibnfc_tf_poll_run = 1;

	libnfc_tf_set_poll_state("thread start", NFC_TF_POLL_STATE_POLLING);

        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = (timeout % 1000) * 1000;

	while ( glibnfc_tf_poll_run ) {
		if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_POLLING ){
			/* tag polling */
			pthread_mutex_lock( &gNfcPollMutex );
			memset( &gNfcPollCmdBuf, 0, sizeof(libnfc_tf_SendCmd_t));
			gNfcFindMediaConf.holding = 0x02;
			libnfc_tf_set_findmedia_command( &gNfcPollCmdBuf, &gNfcFindMediaConf );
			pthread_mutex_unlock( &gNfcPollMutex );

			ret = libnfc_tf_send_command_timeout( &gNfcPollCmdBuf, &t_val );
			if ( ret == NFC_TF_SUCCESS ){
				// RICOH MOD-S for NFC Error Recovery
				//glibnfc_tf_poll_reset_cnt = NFC_TF_RESET_COUNT;
				poll_error_detected_first_time = -1;
				poll_error_detected_last_time = -1;
				// RICOH MOD-E for NFC Error Recovery
				if ( gNfcPollCmdBuf.r_buffer[4] > 0 ){
					/* tag detect */
					libnfc_tf_set_poll_state("tag detect", NFC_TF_POLL_STATE_HOLDING);

					detect_data.data = &gNfcPollCmdBuf.r_buffer[4];
					detect_data.len = gNfcPollCmdBuf.r_buffer[2];
					detect_data.len += (uint32_t)(gNfcPollCmdBuf.r_buffer[3] << 8);
				
					if ( gNfcCallback.detect_cb != NULL ){
						ALOGI("tag detect on, callback run");
						(*gNfcCallback.detect_cb)( &detect_data );
					} else{
						ALOGE("tag detect on, callback not found");
						tag_lost = 1;
					}
				}
			} else {
				// RICOH MOD-S for NFC Error Recovery
				long t = (long) time(NULL);
				ALOGW("Find Media Fail: [%d] time[%ld]", ret, t);
				if (poll_error_detected_first_time == -1) {
					poll_error_detected_first_time = t;
				}
				long diff = t - poll_error_detected_last_time;
				if ((poll_error_detected_last_time != -1) && ((diff < 0) || (diff > 1))) {
					ALOGW("System Time Change");
					poll_error_detected_first_time = t;
				}
				poll_error_detected_last_time = t;
				//glibnfc_tf_poll_reset_cnt--;
				//if (glibnfc_tf_poll_reset_cnt <= 0) {
					//glibnfc_tf_poll_reset_cnt = NFC_TF_RESET_COUNT;
				if ((t - poll_error_detected_first_time) >= NFC_TF_ERROR_RESET_TIMEOUT_VALUE) {
					poll_error_detected_first_time = -1;
					poll_error_detected_last_time = -1;
					// RICOH MOD-E for NFC Error Recovery
					if (gNfcCallback.reset_cb != NULL) {
						ALOGE("Find Media Error %d Over, reset callback run", NFC_TF_RESET_COUNT);
						(*gNfcCallback.reset_cb)();
					} else {
						ALOGE("reset callback not found");
					}
				}
			}
		}
		else if ( (glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HOLDING) ||
			  (glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HANDLED_P2P_POLLING) ){

			query = libnfc_tf_get_query_state();
			if ( query == NFC_TF_QUERYSTATE_HOLDING ){
				pthread_mutex_lock( &gNfcPollMutex );
				memset( &gNfcPollCmdBuf, 0, sizeof(libnfc_tf_SendCmd_t));
				gNfcFindMediaConf.holding = 0x02;
				libnfc_tf_set_findmedia_command( &gNfcPollCmdBuf, &gNfcFindMediaConf );
				pthread_mutex_unlock( &gNfcPollMutex );

				ret = libnfc_tf_send_command_timeout( &gNfcPollCmdBuf, &t_val );
				if ( ret == NFC_TF_SUCCESS ){
					if ( gNfcPollCmdBuf.r_buffer[4] == 0x00 ){
						/* tag lost */
						tag_lost = 1;
					}
					else {
						if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HANDLED_P2P_POLLING ){
							/* p2p polling */
							libnfc_tf_llcp_aceept_polling();
						}
					}
				}
// RICOH ADD-S G2 Porting  暫定修正
//     HANDLEDでないのでカウントは0
                            holdingCount = 0;
// RICOH ADD-E G2 Porting  暫定修正
			}
// RICOH ADD-S G2 Porting  暫定修正
//     TODO  以下の処理は要検討、カウンタは実測から4秒程度
                        if ( query == NFC_TF_QUERYSTATE_HANDLED ) {
                            if ( ++holdingCount >= 10 ) {
                                tag_lost = 1;
                                holdingCount = 0;
                            }
                        }
                        else {
                            holdingCount = 0;
                        }
// RICOH ADD-E G2 Porting  暫定修正
		}

		if ( tag_lost ){
			tag_lost = 0;
			if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HANDLED_P2P_POLLING ){
				libnfc_tf_llcp_tag_lost();
			}
			if ( glibnfc_tf_poll_state != NFC_TF_POLL_STATE_POLLING ){
				if ( gNfcCallback.lost_cb != NULL ){
					ALOGI("tag lost callback run");
					(*gNfcCallback.lost_cb)( NULL );
				}	
			}
			libnfc_tf_poll_free_media();
			libnfc_tf_set_poll_state("tag lost", NFC_TF_POLL_STATE_POLLING);
		}

		usleep( NFC_TF_POLLING_LOOP_SLEEP_USEC );
		log_cnt -= NFC_TF_POLLING_LOOP_SLEEP_USEC;
		if (log_cnt <= 0) {
			log_cnt = NFC_TF_POLLING_LOOP_LOG_USEC;
			ALOGI("Polling thread is active");
		}
	}

	libnfc_tf_llcp_tag_lost();

	libnfc_tf_poll_free_media();

	libnfc_tf_set_poll_state("thread end", NFC_TF_POLL_STATE_INIT);
	glibnfc_tf_poll_run = 0;

	return 0;
}

void libnfc_tf_poll_repolling( void )
{
#ifdef NFC_TF_DEBUG	
	int query;

	query = libnfc_tf_get_query_state();
	ALOGE( "%s : query = %d", __FUNCTION__, query );
#endif

	if ( ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_INIT ) ||
	     ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_POLLING) ){
		return ;
	}
	else if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HANDLED_P2P_POLLING ){
		libnfc_tf_llcp_tag_lost();
	}
	
	libnfc_tf_poll_free_media();
	libnfc_tf_set_poll_state("repolling", NFC_TF_POLL_STATE_POLLING);

}

void libnfc_tf_poll_p2p_start( void )
{
	if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HOLDING ){
		libnfc_tf_set_poll_state("p2p start", NFC_TF_POLL_STATE_HANDLED_P2P_POLLING);
	}
}

void libnfc_tf_poll_p2p_stop( void )
{
	if ( glibnfc_tf_poll_state == NFC_TF_POLL_STATE_HANDLED_P2P_POLLING ){
		libnfc_tf_llcp_tag_lost();
		libnfc_tf_poll_free_media();
		libnfc_tf_set_poll_state("p2p stop", NFC_TF_POLL_STATE_POLLING);
	}
}

// RICOH ADD-S Felica Security Access
int libnfc_tf_set_felica_system_code( uint8_t *systemCode )
{
	ALOGD( "%s", __FUNCTION__ );
	ALOGD( "systemCode[0]=%x systemCode[1]=%x", systemCode[0], systemCode[1] );
	
	pthread_mutex_lock( &gNfcPollMutex );
	if( systemCode[0] == NFC_TF_SYSTEM_CODE_WILD_CARD && systemCode[1] == NFC_TF_SYSTEM_CODE_WILD_CARD ) {
		gNfcSystemCodeConf.felica_systemcode_search = NFC_TF_FELICA_SYSTEM_CODE_DISABLE;
		gNfcSystemCodeConf.felica_systemcode[0] = NFC_TF_SYSTEM_CODE_INITIAL;
		gNfcSystemCodeConf.felica_systemcode[1] = NFC_TF_SYSTEM_CODE_INITIAL;
	} else {
		gNfcSystemCodeConf.felica_systemcode_search = NFC_TF_FELICA_SYSTEM_CODE_ENABLE;
		memcpy(gNfcSystemCodeConf.felica_systemcode, systemCode, NFC_TF_SYSTEM_CODE_LENGTH);
	}
	pthread_mutex_unlock( &gNfcPollMutex );

	return 0;
}
// RICOH ADD-E Felica Security Access

// RICOH ADD-S NDEF Detection Settings
int libnfc_tf_change_findmedia_config( int configType, int configValue )
{
	ALOGI( "Change FindMedia Config: %d %d", configType, configValue );

	int ret = NFC_TF_ERR;
	if ( configType == NFC_TF_FINDMEDIA_CONFIG_TYPE_NDEF_SETTINGS) {
		pthread_mutex_lock( &gNfcPollMutex );
		if ( configValue == NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE ) {
			glibnfc_tf_ndef_detection_settings = NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE;
			ret = NFC_TF_SUCCESS;
		} else if ( configValue == NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_ENABLE ) {
			glibnfc_tf_ndef_detection_settings = NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_ENABLE;
			ret = NFC_TF_SUCCESS;
		}
		pthread_mutex_unlock( &gNfcPollMutex );
	}

	return ret;
}
// RICOH ADD-E NDEF Detection Settings
