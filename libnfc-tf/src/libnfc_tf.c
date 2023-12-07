/*
 *
 * licensed under the Apache License, Version 2.0 (the "License");
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

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
// RICOH ADD-S G2 Porting
#include <string.h>
#include <stdlib.h>
// RICOH ADD-E G2 Porting
#include "libnfc_tf_hal.h"
#include "libnfc_tf.h"
#include "libnfc_tf_local.h"

// GP_NFC HCL Uncommented for Debug logs
#ifdef NFC_TF_DEBUG
#define DEBUG_CMD_DUMP 1
#endif
// GP_NFC HCL Uncommented for Debug logs


// RICOH CHG-S Porting No.3738 2016/12/20
//#define NFC_TF_CMD_RESPONSE_TIMEOUT	500000	/* 500ms */
#define NFC_TF_CMD_RESPONSE_TIMEOUT	1000000	/* 1000ms */
/* RICOH CHG-E Porting No.3738 2016/12/20 */

#define NFC_TF_TAG_ID_LEN		12
#define NFC_TF_CONNECT_TRY_CNT		5

typedef struct {
	int media_count;
	int protocol;
	int media;
	int id_length;
	unsigned char id[NFC_TF_TAG_ID_LEN];
	int hw_media_handle;
} libnfc_tf_tag_info_raw_t;

typedef struct {
	pthread_mutex_t         mutex;
	libnfc_tf_SendCmd_t	cmd;
	uint8_t			result_code;
} libnfc_tf_hw_cmd_mgr_t;

typedef struct {
	pNfcTagDetectRespCallback_t callback;
	void *pdata;
} libnfc_tf_tag_detect_callback_t;

typedef struct {
	pNfcTagDetectRespCallback_t callback;
	void *pdata;
} libnfc_tf_tag_lost_callback_t;

typedef struct {
	pNfcTagDetectRespCallback_t callback;
	void *pdata;
} libnfc_tf_reset_callback_t;

typedef struct {
	int				hw_status;

	libnfc_tf_hw_cmd_mgr_t		hw_cmd_mgr;

	libnfc_tf_tag_info_raw_t	tag_detect_info_raw;

	pthread_t			hw_poll_thraed;

	libnfc_tf_tag_detect_callback_t	tag_detect_cb;
	libnfc_tf_tag_lost_callback_t	tag_lost_cb;
	libnfc_tf_reset_callback_t	reset_cb;
	libnfc_tf_TagDetectInfo_t	tag_detect_infolist;

} libnfc_tf_context_t;


libnfc_tf_context_t gNfcContext;
// RICOH ADD-S Felica Security Access
static libnfc_tf_GetInformationResult_t gNfcGetInformationResult;
// RICOH ADD-E Felica Security Access



#define NFC_TF_CMD_SEND_MUTEX_LOCK()	{ pthread_mutex_lock( &gNfcContext.hw_cmd_mgr.mutex ); }
#define NFC_TF_CMD_SEND_MUTEX_UNLOCK()    { pthread_mutex_unlock( &gNfcContext.hw_cmd_mgr.mutex ); }

static void libnfc_tf_nfc_detect_callback(void *dat);
static void libnfc_tf_nfc_taglost_callback(void *dat);
static void libnfc_tf_nfc_reset_callback(void);

static void libnfc_tf_debug_cmd_dump( uint8_t *cmd, uint32_t len )
{
#ifdef DEBUG_CMD_DUMP
	uint32_t i;
	char str[NFC_TF_CMD_PKT_MAX*4+1];
	for ( i = 0; i < len; i++ ){
		sprintf(&str[i*3], "%02x ", cmd[i] );
	}
	str[i*3] = '\0';
	ALOGE( "%s", str );
#endif
}

static int libnfc_tf_hw_getstatus( void )
{
	return gNfcContext.hw_status;
}

static int libnfc_tf_hw_setstatus(const char *tag, int status)
{
	if ( status < 0 || status >= NFC_HW_STATUS_MAX ){
		ALOGE("[%s]hw status not found[%d]", tag, status);
		return -1;
	}

	if (gNfcContext.hw_status != status) {
		ALOGI("[%s]hw status change [%d] >> [%d]", tag, gNfcContext.hw_status, status);
	}
	gNfcContext.hw_status = status;
	return 0;
}

uint8_t libnfc_tf_get_bcc( uint8_t *buf, uint32_t len )
{
	uint8_t bcc = 0x00;
	uint32_t i;
	
	for ( i = 0; i < len; i++ ){
		bcc ^= *buf;
		buf++;
	}

	return bcc;
}

static int libnfc_tf_result_packet_check( uint8_t *buf, uint32_t len )
{
	uint8_t header = 0;
	uint8_t result = 0;
	uint32_t length = 0;
	uint8_t bcc, bcc_chk;

	if ( buf == NULL ){
		ALOGE( "packet check error buf is null" );
		return -1;
	}

	header = buf[0];
	if ( (header == NFC_TF_CMD_HEADER_NACK) ||
	     (header != NFC_TF_CMD_HEADER_RESULT) ){
	    ALOGE( "packet check header error" );
		return -1;
	}

	/* header + result + length[2] + bcc = 5 */
	if ( len < 5 ){
		ALOGE( "packet check len error" );
		return -1;
	}

	result = buf[1];
	if ( result != NFC_TF_CMD_RESULT_SUCCEEDED ){
		ALOGE( "packet check result error" );
		return -1;
	}

	length = buf[2] | (uint32_t)(buf[3] << 8);
	if ( length > len - 5 ){
		ALOGE( "packet check length error" );
		return -1;
	}

	bcc = buf[len -1];
	bcc_chk = libnfc_tf_get_bcc( buf, len - 1 );
	if ( bcc != bcc_chk ){
		ALOGE( "packet check bcc error" );
		return -1;
	}

	return 0;
}

static int libnfc_tf_command_params_encryption( uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len )
{
	uint8_t command;
	int param_len;
	uint8_t param_buf[NFC_TF_CMD_PKT_MAX];
	uint8_t enc_buf[NFC_TF_CMD_PKT_MAX];
	int padding;

	command = in_data[1];

	/* command packet : HEADER[1] COMMAND[1] LENGTH[2] PARAMS[0..496] BCC[1] */
	param_len = in_len - 5;
	padding = 15 - (param_len % 16);
	memcpy( param_buf, &in_data[4], param_len);
	if ( padding >= 1 ){
		memset( &param_buf[param_len], 0x00, padding );
	}
	param_buf[param_len + padding] = (uint8_t)padding;
	param_len += padding + 1;

	libnfc_tf_secure_params_encrypt( param_buf, enc_buf, param_len, AES_ENCRYPT );
	
	libnfc_tf_set_com_header( &out_data[0], command, param_len );
	memcpy( &out_data[4], &enc_buf[0], param_len );
	libnfc_tf_insert_bcc( &out_data[0], param_len + 4 );
	*out_len = param_len + 5;
#ifdef NFC_TF_DEBUG
	ALOGE( "params encrypt : padding=%d", padding );
#endif

	return NFC_TF_SUCCESS;
}

static int libnfc_tf_command_params_decryption( uint8_t *in_data, uint32_t in_len, uint8_t *out_data, uint32_t *out_len )
{
	int param_len;
	uint8_t param_buf[NFC_TF_CMD_PKT_MAX];
	uint8_t enc_buf[NFC_TF_CMD_PKT_MAX];
	int padding;

	if ( in_len == 5 ){
		memcpy( out_data, in_data, 5 );
		*out_len = 5;
#ifdef NFC_TF_DEBUG
		ALOGE( "empty params length" );
#endif
		return NFC_TF_SUCCESS;
	}

	/* command packet : HEADER[1] COMMAND[1] LENGTH[2] PARAMS[0..496] BCC[1] */
	param_len = in_len - 5;
	memcpy( enc_buf, &in_data[4], param_len );
	libnfc_tf_secure_params_encrypt( enc_buf, param_buf, param_len, AES_DECRYPT );

	padding = param_buf[param_len - 1];
	if ( padding < 0 || padding > 15 ){
#ifdef NFC_TF_DEBUG
		ALOGE( "params decrypt error : padding=%d", padding );
#endif
		return NFC_TF_ERR_ENCRYPT;
	}

	param_len -= padding + 1;
	out_data[0] = in_data[0];
	out_data[1] = in_data[1];
	out_data[2] = (uint8_t)(param_len & 0xff);
	out_data[3] = (uint8_t)((param_len >> 8) & 0xff);
	memcpy( &out_data[4], &param_buf[0], param_len );
	libnfc_tf_insert_bcc( &out_data[0], param_len + 4 );
	*out_len = param_len + 5;
#ifdef NFC_TF_DEBUG
	ALOGE( "params decrypt : padding=%d", padding );
#endif

	return NFC_TF_SUCCESS;
}

static int libnfc_tf_send_recv_command_raw( libnfc_tf_SendCmd_t *cmd, struct timeval *timeout )
{
	int ret;

        ret = libnfc_tf_hal_write( cmd->s_buffer, cmd->s_length );
        if ( ret <= 0 ){
                return NFC_TF_ERR;
        }

        ret = libnfc_tf_hal_read_timeout( cmd->r_buffer, NFC_TF_CMD_PKT_MAX, timeout );
        if ( ret <= 0 ){
                return (ret == 0) ? NFC_TF_ERR_TIMEOUT: NFC_TF_ERR;
        }

	cmd->r_length = ret;

	return NFC_TF_SUCCESS;
}

int libnfc_tf_send_command( libnfc_tf_SendCmd_t *tf_cmd )
{
	return libnfc_tf_send_command_timeout( tf_cmd, NULL );
}

int libnfc_tf_send_command_timeout_and_wait( libnfc_tf_SendCmd_t *tf_cmd, struct timeval *timeout_val, int usec )
{
	int ret = libnfc_tf_send_command_timeout(tf_cmd, timeout_val);
	usleep(usec);
	return ret;
}

int libnfc_tf_send_command_timeout( libnfc_tf_SendCmd_t *tf_cmd, struct timeval *timeout_val )
{
	int ret = 0;
	libnfc_tf_hw_cmd_mgr_t *cmd_mgr = &gNfcContext.hw_cmd_mgr;
	uint8_t *r_buf;
	uint32_t r_len;
	struct timeval t_val;
	int params_encrypt = 0;
	int secure_mode, enc_check;

	if ( tf_cmd == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	if ( tf_cmd->s_length > NFC_TF_CMD_PKT_MAX ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	NFC_TF_CMD_SEND_MUTEX_LOCK();

	memset( &cmd_mgr->cmd, 0, sizeof(cmd_mgr->cmd) );

        secure_mode = libnfc_tf_secure_get_mode();
        enc_check = libnfc_tf_secure_params_encrypt_check( tf_cmd->s_buffer[1] );
        if ( (secure_mode == NFC_TF_SECURE_MODE_SECURE_HOST) && (enc_check == 1) ){
		params_encrypt = 1;
	}

	if ( params_encrypt == 0 ){ 
		memcpy( cmd_mgr->cmd.s_buffer, tf_cmd->s_buffer, tf_cmd->s_length );
		cmd_mgr->cmd.s_length = tf_cmd->s_length;
	}
	else{
		libnfc_tf_command_params_encryption( tf_cmd->s_buffer, tf_cmd->s_length, cmd_mgr->cmd.s_buffer, &cmd_mgr->cmd.s_length );
	}

	if ( timeout_val == NULL ){
// RICOH MOD-S G2 Porting
		t_val.tv_sec = NFC_TF_CMD_RESPONSE_TIMEOUT/1000000;
		t_val.tv_usec = NFC_TF_CMD_RESPONSE_TIMEOUT % 1000000;
//		t_val.tv_sec = 0;
//		t_val.tv_usec = NFC_TF_CMD_RESPONSE_TIMEOUT;
// RICOH MOD-E G2 Porting
	}
	else {
		t_val.tv_sec = timeout_val->tv_sec;
		t_val.tv_usec = timeout_val->tv_usec;
	}

#ifdef DEBUG_CMD_DUMP
	ALOGE( "Send:");
	libnfc_tf_debug_cmd_dump( cmd_mgr->cmd.s_buffer, cmd_mgr->cmd.s_length );
#endif
	ret = libnfc_tf_send_recv_command_raw( &cmd_mgr->cmd, &t_val );
	if ( ret != NFC_TF_SUCCESS ){
#ifdef NFC_TF_DEBUG
		ALOGE( "libnfc_tf_send_recv_command_raw : error ret = %d", ret );
#endif
		NFC_TF_CMD_SEND_MUTEX_UNLOCK();
		return ret;
	}

#ifdef DEBUG_CMD_DUMP
        ALOGE( "Recv:");
        libnfc_tf_debug_cmd_dump( cmd_mgr->cmd.r_buffer, cmd_mgr->cmd.r_length );
#endif

	r_buf = cmd_mgr->cmd.r_buffer;
	r_len = cmd_mgr->cmd.r_length;
	memcpy( tf_cmd->r_buffer, r_buf, r_len );
	tf_cmd->r_length = r_len;

	ret = libnfc_tf_result_packet_check( r_buf, r_len );
	if ( ret < 0 ){
		cmd_mgr->result_code = ( r_len >= 2 ) ? r_buf[1]: 0xff;
#ifdef NFC_TF_DEBUG
                ALOGE( "libnfc_tf_result_packet_check : error ret = %d  result_code = %d", ret, cmd_mgr->result_code );
#endif
		NFC_TF_CMD_SEND_MUTEX_UNLOCK();
		return NFC_TF_ERR_RESPONSE;
	}

	if ( params_encrypt == 1 ){
		ret = libnfc_tf_command_params_decryption( r_buf, r_len, tf_cmd->r_buffer, &tf_cmd->r_length );
		if ( ret != NFC_TF_SUCCESS ){
			NFC_TF_CMD_SEND_MUTEX_UNLOCK();
			return ret;
		}
	}

	NFC_TF_CMD_SEND_MUTEX_UNLOCK();

	return NFC_TF_SUCCESS;
}

void libnfc_tf_set_com_header( uint8_t *buf, uint8_t cmd, uint32_t param_len )
{
        buf[0] = NFC_TF_CMD_HEADER_SEND;
        buf[1] = cmd;
        buf[2] = (uint8_t)(param_len & 0xff);
        buf[3] = (uint8_t)((param_len >> 8) & 0xff);
}

void libnfc_tf_insert_bcc( uint8_t *buf, uint32_t len )
{
	buf[len] = libnfc_tf_get_bcc( buf, len );
}


void libnfc_tf_command_set( libnfc_tf_SendCmd_t *tf_cmd, uint8_t cmd, uint8_t *param_buf, uint32_t param_len ){
	uint32_t cmd_len;

	libnfc_tf_set_com_header( tf_cmd->s_buffer, cmd, param_len );
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;	

	if ( param_buf != NULL ){
		memcpy( &tf_cmd->s_buffer[cmd_len], param_buf, param_len );
		cmd_len += param_len;
	}

	libnfc_tf_insert_bcc( &tf_cmd->s_buffer[0], cmd_len );
	cmd_len++;

	tf_cmd->s_length = cmd_len;
}


int libnfc_tf_initialize( void )
{
	int ret;
	int status = gNfcContext.hw_status;
	int i;
	char dev_file[32];

	if ( status > NFC_HW_CLOSED ){
		return NFC_TF_SUCCESS;
	}

	memset( &gNfcContext, 0, sizeof(libnfc_tf_context_t) );

	pthread_mutex_init( &gNfcContext.hw_cmd_mgr.mutex, NULL );

	if ( status == NFC_HW_INIT ){
		libnfc_tf_hw_setstatus("initialize start", NFC_HW_INIT);

		libnfc_tf_hal_initialize();

		for ( i = 0; i < 8; i++ ){
			sprintf( dev_file, "/dev/ttyACM%d", i );
#ifdef NFC_TF_DEBUG
			ALOGE( "tty open %s", dev_file );
#endif
			ret = libnfc_tf_hal_open( dev_file );
			if ( ret < 0 ){
				continue;
			}

			if ( libnfc_tf_get_query_state() != NFC_TF_QUERYSTATE_ERR ){
				break;
			}
			libnfc_tf_hal_close();
		}
		if ( i >= 8 ){
			return NFC_TF_ERR;
		}
	}

	libnfc_tf_hw_setstatus("initialize end", NFC_HW_CLOSED);

	return NFC_TF_SUCCESS;
}

int libnfc_tf_deinitialize( void )
{
	libnfc_tf_hal_close();

	libnfc_tf_hw_setstatus("deinitialize", NFC_HW_INIT);

	return NFC_TF_SUCCESS;
}

int libnfc_tf_open( void )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int status;
	int ret;
	int retry = 3;
	int query;

	status = libnfc_tf_hw_getstatus();
	if ( status == NFC_HW_INIT ){
		return NFC_TF_ERR;
	}
	else if ( status  != NFC_HW_CLOSED ){
                return NFC_TF_SUCCESS;
        }

	while ( retry >= 0 ){
		memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
		libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPEN, NULL, 0 );
		ret = libnfc_tf_send_command( &tf_cmd );
		if ( ret == NFC_TF_SUCCESS ){
			break;
		}

	        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	        libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSE, NULL, 0 );
        	libnfc_tf_send_command( &tf_cmd );
		retry--;
	}
	
	if ( retry < 0 ){
#ifdef NFC_TF_DEBUG
		query = libnfc_tf_get_query_state();
		ALOGE( "%s : hw open error [query = %d]", __FUNCTION__, query );
#endif
		return NFC_TF_ERR;
	}

	libnfc_tf_set_default_findmedia_config();
	libnfc_tf_llcp_initialize();

	libnfc_tf_hw_setstatus("open", NFC_HW_IDLING);

	return NFC_TF_SUCCESS;
}

int libnfc_tf_open_recognition( int params_enc )
{
	uint8_t challenge_key[16];
	uint8_t challenge_host[16];
	uint8_t host_code[16];
	libnfc_tf_SendCmd_t tf_cmd;
	uint8_t open_cmd;
	int status;
	int ret;
	int retry = 3;
	int query;
	int mode;
	int run_req_recognition = 0;

	status = libnfc_tf_hw_getstatus();
	if ( status == NFC_HW_INIT ){
		return NFC_TF_ERR;
	}
	else if ( status  != NFC_HW_CLOSED ){
		return NFC_TF_SUCCESS;
	}

	if ( params_enc == NFC_TF_SECURE_MODE_NONE ){
		return NFC_TF_ERR;
	}

	mode = libnfc_tf_secure_get_mode();
	if ( mode == NFC_TF_SECURE_MODE_NONE ){
		return NFC_TF_ERR;
	}

	memset( challenge_key, 0, sizeof(challenge_key) );
	libnfc_tf_hal_get_random( challenge_key, sizeof(challenge_key) );

	if ( params_enc == NFC_TF_SECURE_MODE_SECURE_HOST ){
		open_cmd = NFC_TF_CMD_COM_OPENSECURE_RECOGNITION;
	}
	else{
		open_cmd = NFC_TF_CMD_COM_OPEN_RECOGNITION;
	}

	while (retry >= 0) {
		query = libnfc_tf_get_query_state();
		run_req_recognition = 0;
		ALOGI("%s  now state[%d], retry count[%d]", __FUNCTION__, query, retry);
		switch (query) {
			case NFC_TF_QUERYSTATE_LOADING:
				ALOGI("%s  run command[CompleteLoading]", __FUNCTION__);
				memset(&tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t));
				libnfc_tf_command_set(&tf_cmd, NFC_TF_CMD_COM_COMPLETE_LOAD, NULL, 0);
				ret = libnfc_tf_send_command(&tf_cmd);
				if (ret != NFC_TF_SUCCESS) {
					ALOGE("%s  command[CompleteLoading] failed[%d]", __FUNCTION__, ret);
					break;
				}
			case NFC_TF_QUERYSTATE_IDLING:
			case NFC_TF_QUERYSTATE_HOLDING:
			case NFC_TF_QUERYSTATE_HANDLED:
				ALOGI("%s  run command[Close]", __FUNCTION__);
				memset(&tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t));
				libnfc_tf_command_set(&tf_cmd, NFC_TF_CMD_COM_CLOSE, NULL, 0);
				ret = libnfc_tf_send_command(&tf_cmd);
				if (ret != NFC_TF_SUCCESS) {
					ALOGE("%s  command[Close] failed[%d]", __FUNCTION__, ret);
					break;
				}
			case NFC_TF_QUERYSTATE_CLOSED:
				ALOGI("%s  run command[OpenWithRecognition/OpenSecureWithRecognition]", __FUNCTION__);
				memset(&tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t));
				libnfc_tf_command_set(&tf_cmd, open_cmd, challenge_key, sizeof(challenge_key));
				ret = libnfc_tf_send_command(&tf_cmd);
				if (ret != NFC_TF_SUCCESS) {
					ALOGE("%s  command[OpenWithRecognition/OpenSecureWithRecognition] failed[%d]", __FUNCTION__, ret);
					break;
				}
			case NFC_TF_QUERYSTATE_RECOGNIZING:
				ALOGI("%s  state is RECOGNIZING", __FUNCTION__);
				run_req_recognition = 1;
				break;
			case NFC_TF_QUERYSTATE_PRIMARY:
				ALOGE("%s  state is PRIMARY", __FUNCTION__);
				break;
			case NFC_TF_QUERYSTATE_ERR:
				ALOGE("%s  command[QueryState] failed", __FUNCTION__);
				break;
			default:
				ALOGE("%s  state is unknown", __FUNCTION__);
				break;
		}
		if (run_req_recognition) {
			/* create host code */
			memcpy( challenge_host, &tf_cmd.r_buffer[20], sizeof(challenge_host) );
			libnfc_tf_secure_get_hostcode( challenge_host, host_code );

			memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
			libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_REQUEST_RECOGNITION, host_code, sizeof(host_code) );
			ret = libnfc_tf_send_command( &tf_cmd );
			if (ret == NFC_TF_SUCCESS) {
				ALOGI("%s  recognition ok", __FUNCTION__);
				if (params_enc == NFC_TF_SECURE_MODE_SECURE_HOST) {
					ALOGI("%s  create params key", __FUNCTION__);
					libnfc_tf_secure_create_paramskey( challenge_host );
				}
				break;
			} else if (tf_cmd.r_buffer[1] == NFC_TF_CMD_RESULT_FAILED_RECOGNITION) {
				ALOGE("%s  recognition failed", __FUNCTION__);
				return NFC_TF_ERR_ENCRYPT;
			}
		}
		retry--;
	}

	if ( retry < 0 ){
#ifdef NFC_TF_DEBUG
		query = libnfc_tf_get_query_state();
		ALOGE( "%s : hw open error [query = %d]", __FUNCTION__, query );
#endif
		return NFC_TF_ERR;
	}

	libnfc_tf_set_default_findmedia_config();
	libnfc_tf_llcp_initialize();

	libnfc_tf_hw_setstatus("open recognition", NFC_HW_IDLING);

	return NFC_TF_SUCCESS;
}

int libnfc_tf_close( void )
{
        libnfc_tf_SendCmd_t tf_cmd;
        int status;
        int ret;

        status = libnfc_tf_hw_getstatus();
        if ( status == NFC_HW_INIT ){
                return NFC_TF_ERR;
        }
        else if ( status == NFC_HW_CLOSED ){
                return NFC_TF_SUCCESS;
        }

	if ( status >= NFC_HW_IDLING_POLLING ){
		libnfc_tf_nfc_polling_stop();
	}

        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
        libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSE, NULL, 0 );
        ret = libnfc_tf_send_command( &tf_cmd );
        if ( ret != NFC_TF_SUCCESS ){
                return NFC_TF_ERR;
        }

        libnfc_tf_hw_setstatus("close", NFC_HW_CLOSED);

        return NFC_TF_SUCCESS;
}

void libnfc_tf_secure_change_close( void )
{
	libnfc_tf_hw_setstatus("secure change close", NFC_HW_CLOSED);
}

int libnfc_tf_get_query_state( void )
{
	int query_state;
	int ret;
	libnfc_tf_SendCmd_t tf_cmd;
/* RICOH ADD-S Porting No.3739 2016/12/20 */
	int timeout = 1000;
	struct timeval t_val;
	t_val.tv_sec = timeout / 1000 + 1;
	t_val.tv_usec = (timeout % 1000) * 1000;
/* RICOH ADD-E Porting No.3739 2016/12/20 */

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_QUERYSTATE, NULL, 0 );

// RICOH CHG-S Porting No.3739 2016/12/20
        //ret = libnfc_tf_send_command( &tf_cmd );
        ret = libnfc_tf_send_command_timeout( &tf_cmd , &t_val);
// RICOH CHG-E Porting No.3739 2016/12/20
        if ( ret != NFC_TF_SUCCESS ){
                return NFC_TF_QUERYSTATE_ERR;
        }

	query_state = (int)tf_cmd.r_buffer[4];

	return query_state;
}

int libnfc_tf_nfc_polling_start( libnfc_tf_FindMediaConfig_t *config )
{
	int status;
	int ret;

        status = libnfc_tf_hw_getstatus();
	if ( status <= NFC_HW_LOADING || status >= NFC_HW_STATUS_MAX ){
		return NFC_TF_ERR;
	}

	if ( status != NFC_HW_IDLING ){
		return NFC_TF_SUCCESS;
	}

	if ( config == NULL ){
		libnfc_tf_set_default_findmedia_config();
	}
	else{
		libnfc_tf_set_findmedia_config( config );
	}

	memset( &gNfcContext.tag_detect_info_raw, 0, sizeof(libnfc_tf_tag_info_raw_t) );

	libnfc_tf_poll_register_detect_callback(libnfc_tf_nfc_detect_callback);
	libnfc_tf_poll_register_taglost_callback(libnfc_tf_nfc_taglost_callback);
	libnfc_tf_poll_register_reset_callback(libnfc_tf_nfc_reset_callback);

	ret = pthread_create( &gNfcContext.hw_poll_thraed, NULL, libnfc_tf_poll_thread, NULL );
	if ( ret != 0 ){
		return NFC_TF_ERR;
	}

	libnfc_tf_hw_setstatus("polling start", NFC_HW_IDLING_POLLING);

	return NFC_TF_SUCCESS;
}

int libnfc_tf_nfc_polling_stop( void )
{
        int status;

        status = libnfc_tf_hw_getstatus();
        if ( status <= NFC_HW_LOADING || status >= NFC_HW_STATUS_MAX ){
                return NFC_TF_ERR;
        }

	libnfc_tf_poll_stop();

	pthread_join( gNfcContext.hw_poll_thraed, NULL );

        memset( &gNfcContext.tag_detect_info_raw, 0, sizeof(libnfc_tf_tag_info_raw_t) );

	gNfcContext.tag_detect_cb.callback = NULL;
	gNfcContext.tag_detect_cb.pdata = NULL;
	gNfcContext.tag_lost_cb.callback = NULL;
	gNfcContext.tag_lost_cb.pdata = NULL;
	gNfcContext.reset_cb.callback = NULL;
	gNfcContext.reset_cb.pdata = NULL;

	libnfc_tf_hw_setstatus("polling stop", NFC_HW_IDLING);

	return NFC_TF_SUCCESS;
}

void libnfc_tf_nfc_restart_polling( void )
{
        int status;
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
        status = libnfc_tf_hw_getstatus();

        if ( status <= NFC_HW_IDLING_POLLING ){
                return;
        }

        memset( &gNfcContext.tag_detect_info_raw, 0, sizeof(libnfc_tf_tag_info_raw_t) );

	libnfc_tf_poll_repolling();

        libnfc_tf_hw_setstatus("polling restart", NFC_HW_IDLING_POLLING);

}


void libnfc_tf_register_highlayer_detect_callback( pNfcTagDetectRespCallback_t cb_func, void* pdata )
{
	if ( cb_func != NULL ){
		gNfcContext.tag_detect_cb.callback = cb_func;
		gNfcContext.tag_detect_cb.pdata = pdata;
	}
}

void libnfc_tf_register_highlayer_lost_callback( pNfcTagDetectRespCallback_t cb_func, void* pdata )
{
	if ( cb_func != NULL ){
		gNfcContext.tag_lost_cb.callback = cb_func;
		gNfcContext.tag_lost_cb.pdata = pdata;
	}
}

void libnfc_tf_register_highlayer_reset_callback(pNfcTagDetectRespCallback_t cb_func, void* pdata) {
	if ( cb_func != NULL ){
		gNfcContext.reset_cb.callback = cb_func;
		gNfcContext.reset_cb.pdata = pdata;
	}
}

static int libnfc_tf_get_detect_felica_info( libnfc_tf_tag_info_raw_t *rawinfo, libnfc_tf_TagInfo_t *taginfo )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int val;
	int ret;
	uint8_t media_index = 0;
	uint8_t idm[8], pmm[8], syscode[2], handle;	

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_OPENMEDIA;
	}

	
	if ( tf_cmd.r_buffer[2] != 0x14 ){
		/* OpenMedia illegal result param length */
		ALOGE("%s  OpenMedia illegal result param length[%02X]", __FUNCTION__, tf_cmd.r_buffer[2]);
		return -NFC_TF_GET_INFO_ERR_ILLEGAL_PARAM_LENGTH;
	}

	handle = tf_cmd.r_buffer[4];
	memcpy( idm, &tf_cmd.r_buffer[6], 8 );
	memcpy( pmm, &tf_cmd.r_buffer[14], 8 );
	memcpy( syscode, &tf_cmd.r_buffer[22], 2 );

	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_CLOSEMEDIA;
	}

	switch ( rawinfo->media ) {
		case NFC_TF_MEDIAS_MEDIA_FELICA:
			val = NFC_TF_MEDIA_FELICA;
			break;
		case NFC_TF_MEDIAS_MEDIA_MOBILE_FELICA:
			val = NFC_TF_MEDIA_MOBILE_FELICA;
			break;
		case NFC_TF_MEDIAS_MEDIA_NDEF:
			val = NFC_TF_MEDIA_NDEF;
			break;
		case NFC_TF_MEDIAS_MEDIA_OTHER:
		default:
			ALOGE("%s  media not supported[%d]", __FUNCTION__, rawinfo->media);
			return -NFC_TF_GET_INFO_ERR_MEDIA_NOT_SUPPORTED;
	}

	taginfo->rf_type = NFC_TF_RFTYPE_FELICA;
	taginfo->media_type = val;
	memcpy( taginfo->tag_type.Felica_Info.IDm, idm, 8 );
	taginfo->tag_type.Felica_Info.IDmLength = 8;
	memcpy( taginfo->tag_type.Felica_Info.PMm, pmm, 8 );
	memcpy( taginfo->tag_type.Felica_Info.SystemCode, syscode, 2 );

	return 0;
}

static int libnfc_tf_get_detect_iso14443a_info( libnfc_tf_tag_info_raw_t *rawinfo, libnfc_tf_TagInfo_t *taginfo )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int val;
	int ret;
	uint8_t media_index = 0;
	uint8_t sak, atqa[2], uid_len, uid[10], handle;


	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
			return -NFC_TF_GET_INFO_ERR_OPENMEDIA;
	}

	if ( tf_cmd.r_buffer[2] != 0x14 ){
		/* OpenMedia illegal result param length */
		ALOGE("%s  OpenMedia illegal result param length[%02X]", __FUNCTION__, tf_cmd.r_buffer[2]);
		return -NFC_TF_GET_INFO_ERR_ILLEGAL_PARAM_LENGTH;
	}

	handle = tf_cmd.r_buffer[4];
	sak = tf_cmd.r_buffer[6];
	memcpy( atqa, &tf_cmd.r_buffer[7], 2 );
	uid_len = tf_cmd.r_buffer[9];
	memcpy( uid, &tf_cmd.r_buffer[10], 10 );

	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_CLOSEMEDIA;
	}

	switch ( rawinfo->media ) {
		case NFC_TF_MEDIAS_MEDIA_MIFARE:
		// トッパンカードR/WではISO/IEC14443-4(Type-4)のNFCタグは、
		// A, Bに関係なくJICSAP(Type-4b)メディアとして認識される。
		// 本仕様によりMifare DESFireのようなType-4aタグを翳すと、
		// FindMediaのリザルトパケットがprotocol:14443A, media:JICSAPで返ってくる。
		// そのためFindMediaの戻りがJICSAPでもMifareとして処理できるようにする。
		case NFC_TF_MEDIAS_MEDIA_JICSAP:
			val = NFC_TF_MEDIA_MIFARE;
			break;
		case NFC_TF_MEDIAS_MEDIA_NDEF:
			val = NFC_TF_MEDIA_NDEF;
			break;
		case NFC_TF_MEDIAS_MEDIA_OTHER:
		default:
			ALOGE("%s  media not supported[%d]", __FUNCTION__, rawinfo->media);
			return -NFC_TF_GET_INFO_ERR_MEDIA_NOT_SUPPORTED;
	}

	taginfo->rf_type = NFC_TF_RFTYPE_ISO14443A;
	taginfo->media_type = val;
	memcpy( taginfo->tag_type.Iso14443A_Info.Uid, uid, 10 );
	taginfo->tag_type.Iso14443A_Info.UidLength = uid_len;
	taginfo->tag_type.Iso14443A_Info.Sak = sak;
	memcpy( taginfo->tag_type.Iso14443A_Info.AtqA, atqa, 2 );

	return 0;
}

static int libnfc_tf_get_detect_iso14443b_info( libnfc_tf_tag_info_raw_t *rawinfo, libnfc_tf_TagInfo_t *taginfo )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int val;
	int ret;
	uint8_t media_index = 0;
	uint8_t atqb[NFC_TF_TAG_ID_LEN], handle;


	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_OPENMEDIA;
	}

	if ( tf_cmd.r_buffer[2] != 0x14 ){
		/* OpenMedia illegal result param length */
		ALOGE("%s  OpenMedia illegal result param length[%02X]", __FUNCTION__, tf_cmd.r_buffer[2]);
		return -NFC_TF_GET_INFO_ERR_ILLEGAL_PARAM_LENGTH;
	}

	handle = tf_cmd.r_buffer[4];
	memcpy( atqb, &tf_cmd.r_buffer[6], NFC_TF_TAG_ID_LEN );

	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_CLOSEMEDIA;
	}

	switch ( rawinfo->media ){
		case NFC_TF_MEDIAS_MEDIA_JICSAP:
			val = NFC_TF_MEDIA_JICSAP;
			break;
		case NFC_TF_MEDIAS_MEDIA_NDEF:
			val = NFC_TF_MEDIA_NDEF;
			break;
		case NFC_TF_MEDIAS_MEDIA_OTHER:
		default:
			ALOGE("%s  media not supported[%d]", __FUNCTION__, rawinfo->media);
			return -NFC_TF_GET_INFO_ERR_MEDIA_NOT_SUPPORTED;
	}

	taginfo->rf_type = NFC_TF_RFTYPE_ISO14443B;
	taginfo->media_type = val;
	memcpy( taginfo->tag_type.Iso14443B_Info.AtqB, atqb, NFC_TF_TAG_ID_LEN );

	return 0;
}

static int libnfc_tf_get_detect_iso15693_info( libnfc_tf_tag_info_raw_t *rawinfo, libnfc_tf_TagInfo_t *taginfo )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int val;
	int ret;
	int flags;
	uint8_t media_index = 0;
	uint8_t dsf, uid[8], handle;
	uint8_t *cmd_buf;
	uint32_t cmd_len;
	int t_out = 0x06;

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_OPENMEDIA;
	}

	if ( tf_cmd.r_buffer[2] != 0x14 ){
		/* OpenMedia illegal result param length */
		ALOGE("%s  OpenMedia illegal result param length[%02X]", __FUNCTION__, tf_cmd.r_buffer[2]);
		return -NFC_TF_GET_INFO_ERR_ILLEGAL_PARAM_LENGTH;
	}

	handle = tf_cmd.r_buffer[4];
	dsf = tf_cmd.r_buffer[6];
	memcpy( uid, &tf_cmd.r_buffer[7], 8 );

	/* Send Reset to Ready command for media state change (QUIET -> READY) */
	cmd_buf = &tf_cmd.s_buffer[0];

	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_THROUGH, (uint32_t) 0x0C ); //header (0x4a)

	cmd_buf[cmd_len] = (uint8_t)(handle & 0xff); //set handler
	cmd_len++;
	cmd_buf[cmd_len] = (uint8_t)t_out;
	cmd_len++;

	cmd_buf[cmd_len] = 0x22; //set flags
	cmd_len++;
	cmd_buf[cmd_len] = 0x26; //set Reset to Ready command
	cmd_len++;
	memcpy(&cmd_buf[cmd_len], uid, 8); //set uid
	cmd_len += 8;

	libnfc_tf_insert_bcc( cmd_buf, cmd_len); // set bcc
	cmd_len++;
	tf_cmd.s_length = cmd_len;
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_RESET_TO_READY;
	}

	/* Send Inventory command for get Response Flags*/
	cmd_buf = &tf_cmd.s_buffer[0];

	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_THROUGH, (uint32_t) 0x06 ); //header (0x4a)

	cmd_buf[cmd_len] = (uint8_t)(handle & 0xff); //set handler
	cmd_len++;
	cmd_buf[cmd_len] = (uint8_t)t_out;  //set timeout
	cmd_len++;

	cmd_buf[cmd_len] = 0x36; //set flags
	cmd_len++;
	cmd_buf[cmd_len] = 0x01; //set inventory command
	cmd_len++;
	cmd_buf[cmd_len] = 0x00;
	cmd_len++;
	cmd_buf[cmd_len] = 0x00;
	cmd_len++; 

	libnfc_tf_insert_bcc( cmd_buf, cmd_len ); //set bcc
	cmd_len++;
	tf_cmd.s_length = cmd_len;
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_SET_INVENTORY;
	}
	flags = tf_cmd.r_buffer[5];

	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_CLOSEMEDIA;
	}

	switch ( rawinfo->media ){
		case NFC_TF_MEDIAS_MEDIA_ICODESLI:
			val = NFC_TF_MEDIA_ICODESLI;
			break;
		case NFC_TF_MEDIAS_MEDIA_NDEF:
			val = NFC_TF_MEDIA_NDEF;
			break;
		case NFC_TF_MEDIAS_MEDIA_OTHER:
		default:
			ALOGE("%s  media not supported[%d]", __FUNCTION__, rawinfo->media);
			return -NFC_TF_GET_INFO_ERR_MEDIA_NOT_SUPPORTED;
	}

	taginfo->rf_type = NFC_TF_RFTYPE_ISO15693;
	taginfo->media_type = val;
	memcpy( taginfo->tag_type.Iso15693_Info.Uid, uid, 8 );
	taginfo->tag_type.Iso15693_Info.UidLength = 8;
	taginfo->tag_type.Iso15693_Info.Dsfid = dsf;
	taginfo->tag_type.Iso15693_Info.Flags = flags;

	return 0;
}

static int libnfc_tf_get_detect_p2pinitiator_info( libnfc_tf_tag_info_raw_t *rawinfo, libnfc_tf_TagInfo_t *taginfo )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int val;
	int ret;
	uint8_t media_index = 0;
	uint8_t handle;
	uint8_t nfcid[10];

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_OPENMEDIA;
	}

	if ( tf_cmd.r_buffer[2] != 0x14 ){
		/* OpenMedia illegal result param length */
		ALOGE("%s  OpenMedia illegal result param length[%02X]", __FUNCTION__, tf_cmd.r_buffer[2]);
		return -NFC_TF_GET_INFO_ERR_ILLEGAL_PARAM_LENGTH;
	}

	handle = tf_cmd.r_buffer[4];
	memcpy( nfcid, &tf_cmd.r_buffer[6], 10 );

	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return -NFC_TF_GET_INFO_ERR_CLOSEMEDIA;
	}

	switch ( rawinfo->media ){
		case NFC_TF_MEDIAS_MEDIA_P2PTARGET:
			val = NFC_TF_MEDIA_P2P_TAGERT;
			break;
		default:
			ALOGE("%s  media not supported[%d]", __FUNCTION__, rawinfo->media);
			return -NFC_TF_GET_INFO_ERR_MEDIA_NOT_SUPPORTED;
	}

	taginfo->rf_type = NFC_TF_RFTYPE_P2PINITIATOR;
	taginfo->media_type = val;
	memcpy( taginfo->tag_type.P2p_Info.NFCID, nfcid, 10 );
	taginfo->tag_type.P2p_Info.NFCID_Length = 10;

	return 0;
}


static void libnfc_tf_nfc_detect_callback( void *dat )
{
	int ret = -1;
	int info_num;
        int status;
        uint8_t *buf;
	libnfc_tf_detect_data_raw_t *detect_dat = (libnfc_tf_detect_data_raw_t*)dat;
	libnfc_tf_tag_info_raw_t *info_raw = &gNfcContext.tag_detect_info_raw;
	libnfc_tf_TagInfo_t *taginfo;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s in", __FUNCTION__ );
#endif

	status = libnfc_tf_hw_getstatus();
	if ( status <= NFC_HW_IDLING ) {
		ALOGE("%s error : hw_status=%d", __FUNCTION__, status);
		return ;
	} 

	libnfc_tf_hw_setstatus("tag detect start", NFC_HW_IDLING_TAG_PROCESSING);

	buf = detect_dat->data;	

	memset( info_raw, 0, sizeof(libnfc_tf_tag_info_raw_t) );
	info_raw->media_count = (int)buf[0];
	info_raw->protocol = (int)buf[1];
	info_raw->media = (int)buf[2];
	info_raw->id_length = (int)buf[3];
	memcpy( info_raw->id, &buf[4], info_raw->id_length );
#ifdef NFC_TF_DEBUG
        ALOGE( "%s media_count=%d protocol=%d type=%d id_len=%d", __FUNCTION__, info_raw->media_count, info_raw->protocol, info_raw->media, info_raw->id_length );
#endif

	memset( &gNfcContext.tag_detect_infolist, 0, sizeof(libnfc_tf_TagDetectInfo_t) );

	info_num = 0;
	taginfo = &gNfcContext.tag_detect_infolist.info[info_num];
	switch ( info_raw->protocol ) {
		case NFC_TF_MEDIAS_RF_FELICA:
			ret = libnfc_tf_get_detect_felica_info( info_raw, taginfo );
			break;

		case NFC_TF_MEDIAS_RF_ISO14443A:
			ret = libnfc_tf_get_detect_iso14443a_info( info_raw, taginfo );
			break;

		case NFC_TF_MEDIAS_RF_ISO14443B:
			ret = libnfc_tf_get_detect_iso14443b_info( info_raw, taginfo );
			break;

		case NFC_TF_MEDIAS_RF_ISO15693:
			ret = libnfc_tf_get_detect_iso15693_info( info_raw, taginfo );
			break;

		case NFC_TF_MEDIAS_RF_P2PINITIATOR:
			ret = libnfc_tf_get_detect_p2pinitiator_info( info_raw, taginfo );
			break;

		default:
			ALOGE("%s  protocol[%d] not supported", __FUNCTION__, info_raw->protocol);
			ret = -NFC_TF_GET_INFO_ERR_PROTOCOL_NOT_SUPPORTED;
			break;
	}

	if ( ret < 0 ){
		ALOGE("%s  get detect info error[%d] protocol[%d], repolling run", __FUNCTION__, ret, info_raw->protocol);
		libnfc_tf_poll_repolling();
		libnfc_tf_hw_setstatus("tag detect error", NFC_HW_IDLING_POLLING);
		return ;
	}

	info_num++;
	gNfcContext.tag_detect_infolist.info_num = info_num;

	if ( info_raw->protocol == NFC_TF_MEDIAS_RF_P2PINITIATOR ){
		libnfc_tf_poll_p2p_start();
	}
	
	if ( gNfcContext.tag_detect_cb.callback != NULL ){
		(*gNfcContext.tag_detect_cb.callback)( &gNfcContext.tag_detect_infolist, gNfcContext.tag_detect_cb.pdata );
	} else {
		ALOGE("%s  tag detect callback not found", __FUNCTION__);
	}
	
	libnfc_tf_hw_setstatus("tag detect end", NFC_HW_HOLDING);

}

static void libnfc_tf_nfc_taglost_callback( void *dat )
{
	int status;
	(void) dat;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s in", __FUNCTION__ );
#endif

        status = libnfc_tf_hw_getstatus();
        if ( status <= NFC_HW_IDLING_TAG_PROCESSING ){
                return ;
        }

	if ( gNfcContext.tag_lost_cb.callback != NULL ){
		(*gNfcContext.tag_lost_cb.callback)( &gNfcContext.tag_detect_infolist, gNfcContext.tag_lost_cb.pdata );
	}

	libnfc_tf_nfc_restart_polling();
}

static void libnfc_tf_nfc_reset_callback(void) {
	if (gNfcContext.reset_cb.callback != NULL) {
		(*gNfcContext.reset_cb.callback)(NULL, gNfcContext.tag_lost_cb.pdata);
	} else {
		ALOGE("%s  reset callback not found", __FUNCTION__);
	}
}

int libnfc_tf_get_id( libnfc_tf_TagInfo_t *tag, uint8_t *o_id, uint32_t *o_len )
{
	uint8_t *id = NULL;
	uint32_t len = 0;
	int ret = -1;

	switch ( tag->rf_type ){
		case NFC_TF_RFTYPE_ISO14443A:
			id = tag->tag_type.Iso14443A_Info.Uid;
			len = tag->tag_type.Iso14443A_Info.UidLength;
			break;

		case NFC_TF_RFTYPE_ISO14443B:
			id = tag->tag_type.Iso14443B_Info.AtqB;
			len = NFC_TF_TAG_ID_LEN;
			break;

		case NFC_TF_RFTYPE_FELICA:
			id = tag->tag_type.Felica_Info.IDm;
			len = tag->tag_type.Felica_Info.IDmLength;
			break;

		case NFC_TF_RFTYPE_ISO15693:
			id = tag->tag_type.Iso15693_Info.Uid;
			len = tag->tag_type.Iso15693_Info.UidLength;
			break;

		case NFC_TF_RFTYPE_P2PINITIATOR:
			id = tag->tag_type.P2p_Info.NFCID;
			len = tag->tag_type.P2p_Info.NFCID_Length;
			break;

		default:
			len = 0;
			break;
	}

	if ( len > 0 ){
		memcpy( o_id, id, len );
		*o_len = len;
		ret = 0;
	}

	return ret;
}

int libnfc_tf_get_media_handle_id( uint8_t *id, uint32_t id_len )
{
        int handle = -1;

        if ( id == NULL || id_len > NFC_TF_TAG_ID_LEN ){
                return -1;
        }

        if ( memcmp( gNfcContext.tag_detect_info_raw.id, id, id_len ) == 0 ){
                handle = gNfcContext.tag_detect_info_raw.hw_media_handle;
        }

#ifdef NFC_TF_DEBUG
	ALOGE( "%s : handle=%d", __FUNCTION__, handle );
	libnfc_tf_debug_cmd_dump( gNfcContext.tag_detect_info_raw.id, id_len );
	libnfc_tf_debug_cmd_dump( id, id_len );
#endif

        return handle;
}

int libnfc_tf_get_media_handle_taginfo( libnfc_tf_TagInfo_t *tag )
{
        uint8_t id[NFC_TF_TAG_ID_LEN];
        uint32_t id_len;
	int handle;
	
        if ( libnfc_tf_get_id( tag, &id[0], &id_len ) != 0 ){
                return -1;
        }

        handle = libnfc_tf_get_media_handle_id( id, id_len );

	return handle;
}

int libnfc_tf_nfc_connect( libnfc_tf_TagInfo_t *tag )
{
        libnfc_tf_SendCmd_t tf_cmd;
	int status, ret, err = 0;
	int cnt = 0;
	uint8_t handle = 0;
	uint8_t media_index = 0;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s tag=%p", __FUNCTION__, tag );
#endif

	if ( tag == NULL ){
		return NFC_TF_ERR;
	}

        status = libnfc_tf_hw_getstatus();

	if ( status < NFC_HW_IDLING_TAG_PROCESSING ) {
#ifdef NFC_TF_DEBUG
		ALOGE( "%s error : hw_status=%d", __FUNCTION__, status );
#endif
		return NFC_TF_ERR;
	}
	while ( status == NFC_HW_IDLING_TAG_PROCESSING ){
		if ( cnt >= NFC_TF_CONNECT_TRY_CNT ){
#ifdef NFC_TF_DEBUG
			ALOGE( "%s error : hw_status=%d", __FUNCTION__, status );
#endif
			return NFC_TF_ERR;
		}

		usleep( 100000 );
		status = libnfc_tf_hw_getstatus();
		cnt++;
        }
	
	ret = libnfc_tf_get_media_handle_taginfo( tag );
	if ( ret < 0 ){
		return NFC_TF_ERR;
	}
	else if ( ret > 0 ){
		return NFC_TF_SUCCESS;
	}
	handle = (uint8_t)(ret & 0xff);

        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
        libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_OPENMEDIA, &media_index, 1 );
        ret = libnfc_tf_send_command( &tf_cmd );
        if ( ret != NFC_TF_SUCCESS ){
                /* command responce error : tag lost */
                libnfc_tf_nfc_restart_polling();
                return NFC_TF_ERR;
        }

	err = 0;
	handle = tf_cmd.r_buffer[4];
	if ( handle > 0 ){
		/* new media handle */
		gNfcContext.tag_detect_info_raw.hw_media_handle = handle;

		libnfc_tf_hw_setstatus("connect", NFC_HW_HANDLED);

	}
	else{
		err = 1;
#ifdef NFC_TF_DEBUG
		ALOGE( "%s : OpenMedia NfcID check failed err=%d", __FUNCTION__, err );
#endif
                libnfc_tf_nfc_restart_polling();
	}

	return ( err ) ? NFC_TF_ERR: NFC_TF_SUCCESS;
}


int libnfc_tf_nfc_disconnect( libnfc_tf_TagInfo_t *tag )
{
       libnfc_tf_SendCmd_t tf_cmd;
        int status, ret;
        uint8_t handle;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s tag=%p", __FUNCTION__, tag );
#endif
        if ( tag == NULL ){
                return NFC_TF_ERR;
        }

        status = libnfc_tf_hw_getstatus();
        if ( status != NFC_HW_HANDLED ){
#ifdef NFC_TF_DEBUG
		ALOGE( "%s error : hw_status = %d", __FUNCTION__, status );
#endif
                return NFC_TF_ERR;
        }

        ret = libnfc_tf_get_media_handle_taginfo( tag );
        if ( ret < 0 ){
                return NFC_TF_ERR;
        }
	else if ( ret == 0 ){
                return NFC_TF_SUCCESS;
        }
	handle = (uint8_t)(ret & 0xff);

        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
        libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_CLOSEMEDIA, &handle, 1 );
        ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		/* command responce error : tag lost */
		libnfc_tf_nfc_restart_polling();
		return NFC_TF_ERR;
	}
	else {
		gNfcContext.tag_detect_info_raw.hw_media_handle = 0;
		libnfc_tf_hw_setstatus("disconnect", NFC_HW_HOLDING);
		return NFC_TF_SUCCESS;
	}
}

// RICOH ADD-S Felica Security Access
int libnfc_tf_get_device_info( uint8_t *recv_buf, uint32_t *recv_len )
{
	int ret;
	uint8_t recv_param[NFC_TF_CMD_PKT_MAX];
	uint32_t cmd_len = 0;
	
	ALOGD( "%s", __FUNCTION__ );

	libnfc_tf_SendCmd_t tf_cmd;
	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_GETINFORMATION, NULL, 0 );
	
	ret = libnfc_tf_send_command( &tf_cmd );
	
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR;
	}
	
	/* result */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_RESULT_RES_ARRAY_NUMBER], NFC_TF_RESULT_LENGTH );
	cmd_len += NFC_TF_RESULT_LENGTH;
	
	/* device code */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_DEVICE_CODE_RES_ARRAY_NUMBER], NFC_TF_DEVICE_CODE_LENGTH );
	cmd_len += NFC_TF_DEVICE_CODE_LENGTH;
	
	/* device version */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_DEVICE_VERSION_RES_ARRAY_NUMBER], NFC_TF_DEVICE_VERSION_LENGTH );
	cmd_len += NFC_TF_DEVICE_VERSION_LENGTH;
	
	/* device serial */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_DEVICE_SERIAL_RES_ARRAY_NUMBER], NFC_TF_DEVICE_SERIAL_LENGTH );
	cmd_len += NFC_TF_DEVICE_SERIAL_LENGTH;
	
	/* firm id */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_FIRM_ID_RES_ARRAY_NUMBER], NFC_TF_FIRM_ID_LENGTH );
	cmd_len += NFC_TF_FIRM_ID_LENGTH;
	
	/* firm version */
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_FIRM_VERSION_RES_ARRAY_NUMBER], NFC_TF_FIRM_VERSION_LENGTH );
	cmd_len += NFC_TF_FIRM_VERSION_LENGTH;
	
	memcpy( recv_buf, &recv_param, cmd_len );
	*recv_len = cmd_len;
	
	return ret;
}
// RICOH ADD-E Felica Security Access


