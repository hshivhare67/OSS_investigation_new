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

#include <libnfc_tf_if.h>
#include <pthread.h>
// RICOH ADD-S G2 Porting
#include <stdlib.h>
#include <string.h>
// RICOH ADD-E G2 Porting
#include "libnfc_tf.h"
#include "libnfc_tf_local.h"

static pthread_mutex_t gNfcTFInterfaceMutex = PTHREAD_MUTEX_INITIALIZER;
static int transceive_timeout = NFC_TF_COM_THROUGH_TIMEOUT;	/* 500msec */
// RICOH ADD-S Felica Security Access
static int glibnfc_tf_if_access_mode = NFC_TF_ACCESS_MODE_COMMUNICATE_THROUGH;
// RICOH ADD-E Felica Security Access

static int libnfc_tf_secure_set_reopen( int secure_mode )
{
	int ret;

	ret = libnfc_tf_open();
	if ( ret == NFC_TF_SUCCESS ){	
		ret = libnfc_tf_secure_change_mode( secure_mode );
		if ( ret == NFC_TF_SUCCESS ){
			ret = libnfc_tf_open_recognition( secure_mode );
		}
	}

	return ret;
}

int libnfc_TF_InitSecureMode( int secure_mode, uint8_t *p_key, uint8_t *r_key )
{
#ifdef NFC_TF_DEBUG
	ALOGE( "%s", __FUNCTION__ );
#endif

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	libnfc_tf_secure_initialize( secure_mode, p_key, r_key );

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_InitOpen( void )
{
	int ret;
	int secure_mode;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s", __FUNCTION__ );
#endif

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	ret = libnfc_tf_initialize();
	if ( ret != NFC_TF_SUCCESS ){
#ifdef NFC_TF_DEBUG
	        ALOGE( "libnfc_tf_initialize() error ret = %d", ret );
#endif
		pthread_mutex_unlock( &gNfcTFInterfaceMutex );
		return NFC_TF_ERR;
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	ret = libnfc_TF_Open();

	return ret;
}

int libnfc_TF_Open( void )
{
	int ret = NFC_TF_SUCCESS;
	int secure_mode;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

        pthread_mutex_lock( &gNfcTFInterfaceMutex );

	secure_mode = libnfc_tf_secure_get_mode();
	if ( secure_mode == NFC_TF_SECURE_MODE_RECOGNITION ){
		ret = libnfc_tf_open_recognition( NFC_TF_SECURE_MODE_RECOGNITION );
		if ( (ret != NFC_TF_SUCCESS) && (ret != NFC_TF_ERR_ENCRYPT) ){
			ret = libnfc_tf_secure_set_reopen( NFC_TF_SECURE_MODE_RECOGNITION );
		}
	}
	else if ( secure_mode == NFC_TF_SECURE_MODE_SECURE_HOST ){
		ret = libnfc_tf_open_recognition( NFC_TF_SECURE_MODE_SECURE_HOST );
		if ( (ret != NFC_TF_SUCCESS) && (ret != NFC_TF_ERR_ENCRYPT) ){
			ret = libnfc_tf_secure_set_reopen( NFC_TF_SECURE_MODE_SECURE_HOST );
		}
	}
	else {
		ret = libnfc_tf_open();
	}
        if ( ret != NFC_TF_SUCCESS ){
                pthread_mutex_unlock( &gNfcTFInterfaceMutex );
                return NFC_TF_ERR;
        }

        pthread_mutex_unlock( &gNfcTFInterfaceMutex );

        return NFC_TF_SUCCESS;
}

int libnfc_TF_Close( void )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
	pthread_mutex_lock( &gNfcTFInterfaceMutex );
	libnfc_tf_close();
	libnfc_tf_deinitialize();
	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_Enable( pNfcTagDetectRespCallback_t cb_func, void* pdata, uint8_t *systemCode )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s cb_func=%p pdata=%p", __FUNCTION__, cb_func, pdata );
#endif
	if ( cb_func == NULL || pdata == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	libnfc_tf_register_highlayer_detect_callback( cb_func, pdata );

	// RICOH ADD-S Felica Security Access
	libnfc_tf_set_felica_system_code( systemCode );
	// RICOH ADD-E Felica Security Access
	
	ret = libnfc_tf_nfc_polling_start( NULL );
	if ( ret != NFC_TF_SUCCESS ){
		pthread_mutex_unlock( &gNfcTFInterfaceMutex );
		return NFC_TF_ERR;
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_Disable( void )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	libnfc_tf_nfc_polling_stop();

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_Connect( libnfc_tf_TagInfo_t *tag )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	ret = libnfc_tf_nfc_connect( tag );
	if ( ret != NFC_TF_SUCCESS ){
		pthread_mutex_unlock( &gNfcTFInterfaceMutex );
		return NFC_TF_ERR;
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_Disconnect( libnfc_tf_TagInfo_t *tag )
{
        int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

        pthread_mutex_lock( &gNfcTFInterfaceMutex );

        ret = libnfc_tf_nfc_disconnect( tag );
        if ( ret != NFC_TF_SUCCESS ){
                pthread_mutex_unlock( &gNfcTFInterfaceMutex );
                return NFC_TF_ERR;
        }

        pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_IsConnected( libnfc_tf_TagInfo_t *tag )
{
	int media_handle;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

        pthread_mutex_lock( &gNfcTFInterfaceMutex );

        media_handle = libnfc_tf_get_media_handle_taginfo( tag );
        if ( media_handle <= 0 ){
                /* no open media */
                pthread_mutex_unlock( &gNfcTFInterfaceMutex );
                return NFC_TF_ERR;
        }

        pthread_mutex_unlock( &gNfcTFInterfaceMutex );

        return NFC_TF_SUCCESS;
}

int libnfc_TF_SendCommand( libnfc_tf_SendCmd_t *tf_cmd )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	ret = libnfc_tf_send_command( tf_cmd );

	return ret;
}

int libnfc_TF_Transceive( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len )
{
	return libnfc_TF_TransceiveTimeout( tag, send_buf, send_len, recv_buf, recv_len, transceive_timeout );
}

int libnfc_TF_TransceiveTimeout( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, int timeout )
{
	libnfc_tf_SendCmd_t tf_cmd;
	struct timeval t_val;
	uint8_t *cmd_buf;
	uint32_t cmd_len, param_len;
	int media_handle;
	int t_out;
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( send_buf == NULL || recv_buf == NULL || recv_len == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	if ( send_len > NFC_TF_CMD_PKT_MAX - 7 ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	// RICOH ADD-S Felica Security Access
	if(glibnfc_tf_if_access_mode == NFC_TF_ACCESS_MODE_FELICA_DATA_ACCESS && tag->rf_type == NFC_TF_RFTYPE_FELICA){
		/* FeliCa Data Access Command Set */
		ret = libnfc_tf_send_felica_access_command_set( tag, send_buf, send_len, recv_buf, recv_len, timeout);
		return ret;
	}
	// RICOH ADD-E Felica Security Access
	
	media_handle = libnfc_tf_get_media_handle_taginfo( tag );
	if ( media_handle <= 0 ){
		/* no open media or err */
		return NFC_TF_ERR;
	}

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	
	cmd_buf = &tf_cmd.s_buffer[0];

	/* header,command,length */
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	param_len = send_len + 2;
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_THROUGH, param_len );

	/* handle */
	cmd_buf[cmd_len] = (uint8_t)(media_handle & 0xff);
	cmd_len++;

	/* timeout (msec) */
	if ( timeout > 0 ){
		for ( t_out = 0x00; t_out < 0x09; t_out++ ){
			if ( timeout < ( 1 << (t_out+3) ) ){
				break;
			}
		}

		t_val.tv_sec = timeout / 1000 + 1;
		t_val.tv_usec = (timeout % 1000) * 1000;

	}
	else{
		t_val.tv_sec = 0;
		t_val.tv_usec = 10000;

		t_out = 1;
	}
	cmd_buf[cmd_len] = (uint8_t)t_out;
	cmd_len++;

	/* through send data */
	memcpy( &cmd_buf[cmd_len], send_buf, send_len );
	cmd_len += send_len;

	/* bcc */
	libnfc_tf_insert_bcc( cmd_buf, cmd_len );
	cmd_len++;

	tf_cmd.s_length = cmd_len;

	ret = libnfc_tf_send_command_timeout( &tf_cmd, &t_val );
	if ( ret != NFC_TF_SUCCESS ){
		return ret;
	}

	cmd_buf = &tf_cmd.r_buffer[0];
	param_len = cmd_buf[2] | (cmd_buf[3] << 8);
	
	memcpy( recv_buf, &cmd_buf[4], param_len );
	*recv_len = param_len;

	return NFC_TF_SUCCESS;
}


int libnfc_TF_CheckNdef( libnfc_tf_TagInfo_t *tag, libnfc_tf_ndef_info_t *chkndef )
{

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
	if ( tag == NULL || chkndef == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	chkndef->NdefCardState = NFC_TF_NDEF_CARD_INVALID;
	chkndef->MaxNdefMsgLength = 0;

	if ( tag->media_type != NFC_TF_MEDIA_NDEF ){
		pthread_mutex_unlock( &gNfcTFInterfaceMutex );
		return NFC_TF_SUCCESS;
	}
	
	chkndef->NdefCardState = NFC_TF_NDEF_CARD_READ_WRITE;
	chkndef->MaxNdefMsgLength = 0xffffffff;

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return NFC_TF_SUCCESS;
}

int libnfc_TF_PutNdefMessage( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len )
{
	libnfc_tf_SendCmd_t tf_cmd;
	int media_handle, ret, status = NFC_TF_SUCCESS;
        uint8_t record_index;

	uint8_t param_buf[NFC_TF_CMD_PKT_PARAM_MAX];
	uint32_t param_len;

	uint8_t *work_ptr, *work_end_ptr;

	uint8_t record, type_len, id_len;
	uint32_t payload_len;
	uint8_t *type, *id, *payload;
	
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	media_handle = libnfc_tf_get_media_handle_taginfo( tag );
	if ( media_handle <= 0 ){
		/* no open media or err */
		return NFC_TF_ERR;
	}

	record_index = 0;
	work_ptr = send_buf;
	work_end_ptr = work_ptr + send_len;

	while ( work_ptr < work_end_ptr ){

#ifdef NFC_TF_DEBUG
		ALOGE( "Put NDEF Recode index=%d", record_index );
#endif

		id_len = payload_len = type_len = record = 0;
		id = payload = type = NULL;

		/* NDEF Record */
		record = *work_ptr;
		type_len = *(work_ptr+1);
		work_ptr += 2;

		if ( record & NFC_TF_NDEF_FLAG_SR ){
			payload_len = *work_ptr;
			work_ptr += 1;
		}
		else {
			payload_len = *(work_ptr+3);
			payload_len |= (*(work_ptr+2)) << 8;
			work_ptr += 4;
		}

		if ( record & NFC_TF_NDEF_FLAG_IL ){
			id_len = *work_ptr;
			work_ptr += 1;
		}

		if ( type_len > 0 ){
			type = work_ptr;
			work_ptr += type_len;
		}
		
		if ( id_len > 0 && ( record & NFC_TF_NDEF_FLAG_IL ) ){
			id = work_ptr;
			work_ptr += id_len;
		}

		if ( payload_len > 0 ){
			payload = work_ptr;
			work_ptr += payload_len;
		}

		if ( work_ptr > work_end_ptr ){
			ALOGE( "Put NDEF data check failed : %p > %p", work_ptr, work_end_ptr );
			status = NFC_TF_ERR_INVALID_PARAM;
			break;
		}

#ifdef NFC_TF_DEBUG
		ALOGE( "work_ptr=%p work_end_ptr=%p recode=%x type_len=%d id_len=%d payload_len=%d", work_ptr, work_end_ptr, record, type_len, id_len, payload_len );
#endif

		/* T.F. Cmd */
		memset( param_buf, 0, sizeof(param_buf) );
		param_len = 0;

		param_buf[param_len] = (uint8_t)media_handle;
		param_len += 1;

		param_buf[param_len] = record & (NFC_TF_NDEF_FLAG_MB|NFC_TF_NDEF_FLAG_ME|NFC_TF_NDEF_FLAG_CF);
		param_len += 1;

		param_buf[param_len] = record & NFC_TF_NDEF_TNF_MASK;
		param_len += 1;

		if ( param_len + (type_len + 2) > NFC_TF_CMD_PKT_PARAM_MAX ){
			ALOGE( "Put NDEF data packet overflow : %d > %d", param_len + id_len, NFC_TF_CMD_PKT_PARAM_MAX );
			status = NFC_TF_ERR_INVALID_PARAM;
			break;
		}

		param_buf[param_len] = type_len;
		param_buf[param_len+1] = 0x00;
		param_len += 2;
		
		if ( type_len > 0 ){
			memcpy( &param_buf[param_len], type, type_len );
			param_len += type_len;
		}


		if ( param_len + (id_len + 2) > NFC_TF_CMD_PKT_PARAM_MAX ){
			ALOGE( "Put NDEF data packet overflow : %d > %d", param_len + id_len, NFC_TF_CMD_PKT_PARAM_MAX );
			status = NFC_TF_ERR_INVALID_PARAM;
			break;
		}

		param_buf[param_len] = id_len;
		param_buf[param_len+1] = 0x00;
		param_len += 2;

		if ( id_len > 0 ){
			memcpy( &param_buf[param_len], id, id_len );
			param_len += id_len;
		}

		if ( param_len + (payload_len + 2) > NFC_TF_CMD_PKT_PARAM_MAX ){
			ALOGE( "Put NDEF data packet overflow : %d > %d", param_len + id_len, NFC_TF_CMD_PKT_PARAM_MAX );
			status = NFC_TF_ERR_INVALID_PARAM;
			break;
		}

		param_buf[param_len] = payload_len;
		param_buf[param_len+1] = 0x00;
		param_len += 2;

		if ( payload_len > 0 ){
			memcpy( &param_buf[param_len], payload, payload_len );
			param_len += payload_len;
		}

	        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
		libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_PUT_NDEF_MESSAGE, param_buf, param_len );
		ret = libnfc_tf_send_command( &tf_cmd );
		if ( ret != NFC_TF_SUCCESS ){
			status = ret;
			break;
		}

		record_index++;

	}

	return status;
}

int libnfc_TF_GetNdefMessage( libnfc_tf_TagInfo_t *tag, uint8_t **o_buf_addr, uint32_t *recv_len )
{
        libnfc_tf_SendCmd_t tf_cmd;
        int media_handle;
	uint8_t cmd_param[2];
        int ret, status = NFC_TF_ERR;
	uint32_t buf_len, ndef_len, work_len;
	uint8_t *buf, *ndef_ptr, *cmd_ptr;

	uint8_t record_index;
	uint8_t	record, *record_prev = NULL;
	uint8_t type_len;
	uint32_t payload_len;
	uint8_t id_len, *type, *id, *payload;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
        if ( tag == NULL || o_buf_addr == NULL || recv_len == NULL ){
                return NFC_TF_ERR_INVALID_PARAM;
        }

        media_handle = libnfc_tf_get_media_handle_taginfo( tag );
        if ( media_handle <= 0 ){
                /* no open media or err */
                return NFC_TF_ERR;
        }

	ndef_len = 0;
	buf_len = 4096;
	ndef_ptr = buf = malloc(buf_len);

        memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	cmd_param[0] = (uint8_t)(media_handle & 0xff);

	record_index = 0;
	do {

#ifdef NFC_TF_DEBUG
		ALOGE( "Get NDEF Recode index=%d", record_index );
#endif

		record = type_len = payload_len = id_len = 0;
		type = id = payload = NULL;

		cmd_param[1] = record_index;
		libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_GET_NDEF_MESSAGE, cmd_param, 2 );
	        ret = libnfc_tf_send_command( &tf_cmd );
		if ( ret != NFC_TF_SUCCESS ){
			break;
		}

		/* params field */	
		cmd_ptr = &tf_cmd.r_buffer[4];
	
		/* TNF */
		record = (*cmd_ptr) & 0x07;
		cmd_ptr += 1;

		/* TYPE_LENGTH */
		type_len = *cmd_ptr;
		cmd_ptr += 2;

		/* TYPE */
		if ( type_len > 0 ){
			type = cmd_ptr;
			cmd_ptr += type_len;
		}

		/* ID_LENGTH */
		id_len = *cmd_ptr;
		cmd_ptr += 2;

		/* ID */
		if ( id_len > 0 ){
			id = cmd_ptr;
			cmd_ptr += id_len;
		}

		/* PAYLOAD_LENGTH */
		payload_len = *cmd_ptr;
		payload_len |= (*(cmd_ptr+1)) << 8;
		cmd_ptr += 2;

		/* PAYLOAD */
		if ( payload_len > 0 ){
			payload = cmd_ptr;
			cmd_ptr += payload_len;
		}

		/* MB flag */
		if ( record_index == 0 ){
			record |= NFC_TF_NDEF_FLAG_MB;
		}

		if ( payload_len <= 0xff ){
			record |= NFC_TF_NDEF_FLAG_SR;
		}		
		else {
			record |= NFC_TF_NDEF_FLAG_CF;
		}

		if ( id_len > 0 ){
			record |= NFC_TF_NDEF_FLAG_IL;
		}

		/* NDEF Record size check */
		work_len = 1;	/* FLAG octet */
		work_len += ( type_len > 0 ) ? type_len + 1 : 1;	/* TYPE LENGTH / TYPE octet */
		work_len += ( record & NFC_TF_NDEF_FLAG_SR ) ? 1 : 4;	/* PAYLOAD LENGTH octet */
		work_len += ( record & NFC_TF_NDEF_FLAG_IL ) ? id_len + 1 : 0;	/* ID LENGTH / ID octet */
		work_len += payload_len;
		if ( ndef_len + work_len > buf_len ){
			buf_len *= 2;
			buf = realloc( buf, buf_len );
			ndef_ptr = buf + ndef_len;
		}

#ifdef NFC_TF_DEBUG
		ALOGE( "record:%x type_len:%x payload_len:%x id_len:%x type=%p id:%p payload:%p",
			record, type_len, payload_len, id_len, type, id, payload );
		ALOGE( "Record Length:%d", work_len );
#endif

		/* NDEF Record */
		record_prev = ndef_ptr;
		*ndef_ptr = record;
		*(ndef_ptr+1) = type_len;
		ndef_ptr += 2;

		if ( record & NFC_TF_NDEF_FLAG_SR ){
			*ndef_ptr = (uint8_t)(payload_len & 0xff);
			ndef_ptr += 1;
		}
		else {
			*ndef_ptr = (uint8_t)((payload_len >> 24) & 0xff);
			*(ndef_ptr+1) = (uint8_t)((payload_len >> 16) & 0xff);
			*(ndef_ptr+2) = (uint8_t)((payload_len >> 8) & 0xff);
			*(ndef_ptr+3) = (uint8_t)(payload_len & 0xff);
			ndef_ptr += 4;
		}

		if ( record & NFC_TF_NDEF_FLAG_IL ){
			*ndef_ptr = id_len;
			ndef_ptr += 1;
		}

		if ( type_len > 0 ){
			memcpy( ndef_ptr, type, type_len );
			ndef_ptr += type_len;
		}

		if ( id_len > 0 && (record & NFC_TF_NDEF_FLAG_IL) ){
			memcpy( ndef_ptr, id, id_len );
			ndef_ptr += id_len;
		}

		if ( payload_len > 0 ){
			memcpy( ndef_ptr, payload, payload_len );
			ndef_ptr += payload_len;
		}

		ndef_len += work_len;

#ifdef NFC_TF_DEBUG
		ALOGE( "buf_ptr:%p buf_len:%d  ndef_ptr:%p ndef_len:%d", buf, buf_len, ndef_ptr, ndef_len );
#endif

		record_index++;

	}while( ret == NFC_TF_SUCCESS );

	if ( ret == NFC_TF_ERR_RESPONSE ){
		if ( record_index > 0 ){
			*record_prev = ((*record_prev) & ~NFC_TF_NDEF_FLAG_CF) | NFC_TF_NDEF_FLAG_ME;

			*o_buf_addr = buf;
			*recv_len = ndef_len;
			status = NFC_TF_SUCCESS;
		}
	}

        return status;
}


int libnfc_TF_Llcp_CreateServerSocket( int miu, int rw, int ssap, uint8_t *service_name, void** handle )
{
	int ret = NFC_TF_ERR;
	void* sock;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	sock = (void*)libnfc_tf_llcp_server_socket( miu, rw, ssap, service_name );
	if ( sock != NULL ){
		*handle = sock;
		ret = NFC_TF_SUCCESS;
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}

int libnfc_TF_Llcp_CreateClientSocket( int miu, int rw, int ssap, void** handle )
{
	int ret = NFC_TF_ERR;
	void* sock;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	sock = (void*)libnfc_tf_llcp_client_socket( miu, rw, ssap );
	if ( sock != NULL ){
		*handle = sock;
		ret = NFC_TF_SUCCESS;
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}


int libnfc_TF_Llcp_Accept( void* handle, int miu, int rw, pNfcTagLlcpAcceptCallback_t cb_func, void* pdata )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL || cb_func == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	ret = libnfc_tf_llcp_accept( (libnfc_tf_llcp_socket_t*)handle, miu, rw, cb_func, pdata );

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}

int libnfc_TF_Llcp_Connect( libnfc_tf_TagInfo_t* tag, void* handle, int dsap )
{
	libnfc_tf_llcp_socket_t *sock = (libnfc_tf_llcp_socket_t*)handle;
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( tag == NULL || handle == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	sock->dsap_number = dsap;
	sock->sap_name_length = 0;

	ret = libnfc_tf_llcp_connect( sock );

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}

int libnfc_TF_Llcp_ConnectBy( libnfc_tf_TagInfo_t* tag, void* handle, uint8_t *service_name )
{
        libnfc_tf_llcp_socket_t *sock = (libnfc_tf_llcp_socket_t*)handle;
	int s_len;
        int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

        if ( tag == NULL || handle == NULL || service_name == NULL ){
                return NFC_TF_ERR_INVALID_PARAM;
        }

	s_len = strlen( (char*)service_name );
	if ( s_len > NFC_TF_LLCP_SERVICE_NAME_MAX_LENGTH ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

        pthread_mutex_lock( &gNfcTFInterfaceMutex );

        sock->dsap_number = 0xff;
        sock->sap_name_length = s_len;
	memcpy( sock->sap_name, service_name, s_len );

        ret = libnfc_tf_llcp_connect( sock );

        pthread_mutex_unlock( &gNfcTFInterfaceMutex );

        return ret;

}

int libnfc_TF_Llcp_Close( void* handle )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	ret = libnfc_tf_llcp_close( (libnfc_tf_llcp_socket_t*)handle );

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}

int libnfc_TF_Llcp_Send( void* handle, uint8_t *buff, uint32_t len )
{
	int ret;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL || buff == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );

	ret = libnfc_tf_llcp_send( (libnfc_tf_llcp_socket_t*)handle, buff, len );

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return ret;
}

int libnfc_TF_Llcp_Recv( void* handle, uint8_t *buff, uint32_t buff_len )
{
	int recv_len = 0;
	int retry;

#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL || buff == NULL ){
		return -1;
	}

	pthread_mutex_lock( &gNfcTFInterfaceMutex );	

	recv_len = libnfc_tf_llcp_recv( (libnfc_tf_llcp_socket_t*)handle, buff, buff_len );
	if ( recv_len == 0 ){
		for ( retry = 0; retry < 10; retry++ ){
			recv_len = libnfc_tf_llcp_recv( (libnfc_tf_llcp_socket_t*)handle, buff, buff_len );
			if ( recv_len > 0 ){
				break;
			}
			usleep( 100000 );
		}
	}

	pthread_mutex_unlock( &gNfcTFInterfaceMutex );

	return recv_len;
}

int libnfc_TF_Llcp_GetRemoteSockMiu( void* handle )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL ){
		return 0;
	}

	return NFC_TF_LLCP_MIU_DEFAULT;
}

int libnfc_TF_Llcp_GetRemoteSockRW( void* handle )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif

	if ( handle == NULL ){
		return 0;
	}

	return NFC_TF_LLCP_RW_DEFAULT;
}

int libnfc_TF_LostRespCbRegister(pNfcTagLostRespCallback_t cb_func, void* pdata)
{
#ifdef NFC_TF_DEBUG
	ALOGE( "%s", __FUNCTION__ );
#endif
	libnfc_tf_register_highlayer_lost_callback(cb_func, pdata);
	return NFC_TF_SUCCESS;
}

int libnfc_TF_RestRespCbRegister(pNfcTagLostRespCallback_t cb_func, void* pdata) {
#ifdef NFC_TF_DEBUG
	ALOGE( "%s", __FUNCTION__ );
#endif
	libnfc_tf_register_highlayer_reset_callback(cb_func, pdata);
	return NFC_TF_SUCCESS;
}

int libnfc_TF_SetTransceiveTimeout( int timeout )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s : set timeout %d ms", __FUNCTION__, timeout );
#endif
	transceive_timeout = timeout;

	return NFC_TF_SUCCESS;
}

int libnfc_TF_ResetTransceiveTimeout( void )
{
#ifdef NFC_TF_DEBUG
        ALOGE( "%s", __FUNCTION__ );
#endif
        transceive_timeout = NFC_TF_COM_THROUGH_TIMEOUT;

	return NFC_TF_SUCCESS;
}

int libnfc_TF_Change_SecureMode( int secure_on )
{
	int mode;
	int new_mode;
	int ret;

#ifdef NFC_TF_DEBUG
	ALOGE( "%s : secure flag = %d", __FUNCTION__, secure_on );
#endif

	mode = libnfc_tf_secure_get_mode();
	new_mode = secure_on;

        if ( mode == NFC_TF_SECURE_MODE_NONE ){
                ret = libnfc_tf_open();
        }
        else{
                ret = libnfc_tf_open_recognition( NFC_TF_SECURE_MODE_RECOGNITION );
        }
        if ( ret != NFC_TF_SUCCESS ){
#ifdef NFC_TF_DEBUG
		ALOGE( "%s : open error", __FUNCTION__ );
#endif
                return NFC_TF_ERR;
        }

	ret = libnfc_tf_secure_change_mode( new_mode );
	if ( ret != NFC_TF_SUCCESS ){
#ifdef NFC_TF_DEBUG
		ALOGE( "%s : secure mode change error", __FUNCTION__ );
#endif
		return NFC_TF_ERR;
	}

	return NFC_TF_SUCCESS;
}

int libnfc_TF_HW_FailCheck( int timeout_ms )
{
	libnfc_tf_SendCmd_t tf_cmd;
	struct timeval t_val;
	int ret;

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_QUERYSTATE, NULL, 0 );

	t_val.tv_sec = timeout_ms / 1000;
	t_val.tv_usec = (timeout_ms % 1000) * 1000;
	ret = libnfc_tf_send_command_timeout( &tf_cmd, &t_val );
	if ( ret == NFC_TF_ERR_TIMEOUT ){
		return NFC_TF_ERR;
	}

	return NFC_TF_SUCCESS;
}

// RICOH ADD-S Felica Security Access
int libnfc_TF_Set_Felica_Access_Mode( int accessMode )
{	
	ALOGD( "%s", __FUNCTION__ );
	ALOGD( "accessMode=%d", accessMode );
	glibnfc_tf_if_access_mode = accessMode;
	return NFC_TF_SUCCESS;
}

int libnfc_TF_Set_Felica_System_Code( uint8_t *systemCode )
{
	ALOGD( "%s", __FUNCTION__ );

	return libnfc_tf_set_felica_system_code( systemCode );
}

int libnfc_TF_Get_Device_Info( uint8_t *recvbuf, uint32_t *recvlen )
{	
	ALOGD( "%s", __FUNCTION__ );
	return libnfc_tf_get_device_info( recvbuf, recvlen );
}

int libnfc_tf_send_felica_access_command_set(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, int timeout ){
	
	int ret;
	uint8_t code;
	struct timeval t_val;
	
	ALOGD( "%s", __FUNCTION__ );
	
	/* timeout (msec) */
	if ( timeout > 0 ){
		t_val.tv_sec = timeout / 1000 + 1;
		t_val.tv_usec = (timeout % 1000) * 1000;
	}
	else{
		t_val.tv_sec = NFC_TF_COM_FELICA_ACCESS_COMMAND_TIMEOUT;
		t_val.tv_usec = 0;
	}
	
	/* command code */
	code = send_buf[NFC_TF_COMMAND_CODE_REQ_ARRAY_NUMBER];
	
	switch( code ){
	// case FELICA_CMD_WRITE_FELICA_ENC:
	//	ret = libnfc_tf_write_felica_without_encryption( tag, send_buf, send_len, recv_buf, recv_len, &t_val );
	//	break;
		
	case FELICA_CMD_READ_FELICA_ENC:
		ret = libnfc_tf_read_felica_without_encryption( tag, send_buf, send_len, recv_buf, recv_len, &t_val );
		break;
		
	case FELICA_CMD_AUTHENTICATE_FELICA:
		ret = libnfc_tf_authenticate_felica( tag, send_buf, send_len, recv_buf, recv_len, &t_val );
		break;
		
	// case FELICA_CMD_WRITE_FELICA:
	//	ret = libnfc_tf_write_felica( tag, send_buf, send_len, recv_buf, recv_len, &t_val );
	//	break;
		
	case FELICA_CMD_READ_FELICA:
		ret = libnfc_tf_read_felica( tag, send_buf, send_len, recv_buf, recv_len, &t_val );
		break;
	
	default:
		ret = NFC_TF_ERR;
		break;
	}
	
	return ret;
}

int libnfc_tf_write_felica_without_encryption(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *t_val)
{
	return NFC_TF_SUCCESS;
}

int libnfc_tf_read_felica_without_encryption(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *t_val)
{
libnfc_tf_SendCmd_t tf_cmd;
	uint8_t *cmd_buf, recv_param[NFC_TF_CMD_PKT_MAX];
	uint32_t cmd_len, data_length;
	int media_handle, ret;

	ALOGD( "%s", __FUNCTION__ );
	
	media_handle = libnfc_tf_get_media_handle_taginfo( tag );
	if ( media_handle <= 0 ){
		return NFC_TF_ERR;
	}
	
	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	cmd_buf = &tf_cmd.s_buffer[0];
	
	/* header, command, length */
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_READ_FELICA_ENC, NFC_TF_READ_FELICA_ENC_SEND_PARAM_LENGTH );
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	
	/* handle number */
	cmd_buf[cmd_len] = (uint8_t)(media_handle & 0xff);
	cmd_len++;
	
	/* service code */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_ENC_SERVICE_CODE_REQ_ARRAY_NUMBER], NFC_TF_SERVICE_CODE_LENGTH );
	cmd_len += NFC_TF_SERVICE_CODE_LENGTH;
	
	/* block type */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_ENC_BLOCK_TYPE_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_TYPE_LENGTH );
	cmd_len += NFC_TF_BLOCK_TYPE_LENGTH;
	
	/* block number */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_ENC_BLOCK_NUMBER_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_NUMBER_LENGTH );
	cmd_len += NFC_TF_BLOCK_NUMBER_LENGTH;
	
	/* block count */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_ENC_BLOCK_COUNT_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_COUNT_LENGTH );
	cmd_len += NFC_TF_BLOCK_COUNT_LENGTH;
	
	/* bcc */
	libnfc_tf_insert_bcc( cmd_buf, cmd_len );
	cmd_len++;
	
	tf_cmd.s_length = cmd_len;
	cmd_len = 0;

// RICOH MOD-S G2 Porting
	ret = libnfc_tf_send_command_timeout( &tf_cmd, t_val );
	//ret = libnfc_tf_send_command_timeout( &tf_cmd, &t_val );
// RICOH MOD-E G2 Porting

	if ( ret != NFC_TF_SUCCESS ){
		return ret;
	}
	
	memset( recv_param, 0, sizeof(recv_param) );
	
	/* length */
	recv_param[cmd_len] = tf_cmd.r_length - 3;/* ( header + result + length[2] + bcc ) - ( commandCode + length[1] ) = 3 */
	cmd_len++;
	
	/* response code */
	recv_param[cmd_len] = FELICA_RES_READ_FELICA_ENC;
	cmd_len++;
	
	/* media status1 */
	recv_param[cmd_len] = tf_cmd.r_buffer[NFC_TF_READ_MEDIA_STATUS_1_RES_ARRAY_NUMBER];
	cmd_len++;
	
	/* media status2 */
	recv_param[cmd_len] = tf_cmd.r_buffer[NFC_TF_READ_MEDIA_STATUS_2_RES_ARRAY_NUMBER];
	cmd_len++;
	
	/* data */
	data_length = tf_cmd.r_buffer[NFC_TF_LENGTH_RES_ARRAY_NUMBER] - ( NFC_TF_MRDIA_STATUS1_LENGTH + NFC_TF_MRDIA_STATUS2_LENGTH );
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_READ_DATA_RES_ARRAY_NUMBER], data_length );
	cmd_len += data_length;
	
	memcpy( recv_buf, &recv_param, cmd_len );
	*recv_len = cmd_len;
	
	return ret;
}

int libnfc_tf_authenticate_felica(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *t_val)
{
	libnfc_tf_SendCmd_t tf_cmd;
	uint8_t *cmd_buf, recv_param[NFC_TF_CMD_PKT_MAX], result_code;
	uint32_t cmd_len;
	int media_handle, ret;

	ALOGD( "%s", __FUNCTION__ );
	
	media_handle = libnfc_tf_get_media_handle_taginfo( tag );
	if ( media_handle <= 0 ){
		return NFC_TF_ERR;
	}

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	cmd_buf = &tf_cmd.s_buffer[0];
	
	/* header, command,length */
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_AUTHENTICATE_FELICA, NFC_TF_AUTH_FELICA_SEND_PARAM_LENGTH );
	
	/* handle number */
	cmd_buf[cmd_len] = (uint8_t)(media_handle & 0xff);
	cmd_len++;
	
	/* area count */
	cmd_buf[cmd_len] = send_buf[NFC_TF_AUTH_AREA_COUNT_REQ_ARRAY_NUMBER];
	cmd_len++;
	
	/* area list */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_AUTH_AREA_LIST_REQ_ARRAY_NUMBER], NFC_TF_AREA_LIST_LENGTH );
	cmd_len += NFC_TF_AREA_LIST_LENGTH;
	
	/* service count */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_AUTH_SERVICE_COUNT_REQ_ARRAY_NUMBER], NFC_TF_SERIVCE_COUNT_LENGTH );
	cmd_len += NFC_TF_SERIVCE_COUNT_LENGTH;
	
	/* service list */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_AUTH_SERVICE_LIST_REQ_ARRAY_NUMBER], NFC_TF_SERVICE_LIST_LENGTH );
	cmd_len += NFC_TF_SERVICE_LIST_LENGTH;

	/* group key usage */
	cmd_buf[cmd_len] = NFC_TF_GROUP_KEY_USAGE_KEY_DIRECTLY;
	cmd_len += NFC_TF_GROUP_KEY_USAGE_LENGTH;
	
	/* group key attribute */
	cmd_buf[cmd_len] = NFC_TF_GROUP_KEY_ATTRIBUTE_KEY_DIRECTLY;
	cmd_len += NFC_TF_GROUP_KEY_ATTRIBUTE_LENGTH;
	
	/* group key */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_AUTH_GROUP_KEY_REQ_ARRAY_NUMBER], NFC_TF_GROUP_KEY_LENGTH );
	cmd_len += NFC_TF_GROUP_KEY_LENGTH;
	
	/* user key usage */
	cmd_buf[cmd_len] = NFC_TF_USER_KEY_USAGE_KEY_DIRECTLY;
	cmd_len += NFC_TF_USER_KEY_USAGE_LENGTH;
	
	/* user key attribute */
	cmd_buf[cmd_len] = NFC_TF_USER_KEY_ATTRIBUTE_KEY_DIRECTLY;
	cmd_len += NFC_TF_USER_KEY_ATTRIBUTE_LENGTH;
	
	/* user key */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_AUTH_USER_KEY_REQ_ARRAY_NUMBER], NFC_TF_USER_KEY_LENGTH );
	cmd_len += NFC_TF_USER_KEY_LENGTH;
	
	/* bcc*/
	libnfc_tf_insert_bcc( cmd_buf, cmd_len );
	cmd_len++;

	tf_cmd.s_length = cmd_len;
	cmd_len = 0;

// RICOH MOD-S G2 Porting
	ret = libnfc_tf_send_command_timeout( &tf_cmd, t_val );
	//ret = libnfc_tf_send_command_timeout( &tf_cmd, &t_val );
// RICOH MOD-E G2 Porting

    result_code = tf_cmd.r_buffer[NFC_TF_RESULT_RES_ARRAY_NUMBER];

	if( result_code == NFC_TF_RESULT_SUCCEEDED || result_code == NFC_TF_RESULT_FAILED_KEY_GENERATION || result_code == NFC_TF_RESULT_FAILED_ENCRYPTION){
		// リザルトコードがSUCCEEDED, FAILED_KEY_GENERATION, FAILED_ENCRYPTIONの時は結果を成功として通知する
		ret = NFC_TF_SUCCESS;
	} else {
		// 上記以外のリザルトコードの場合は、結果をエラーで返す
		return ret;
	}
	
	memset( recv_param, 0, sizeof(recv_param) );
	
	/* length */
	recv_param[cmd_len] = tf_cmd.r_length - 2;/* ( header + length[2] + bcc ) - ( commandCode + length[1] ) = 2 */
	cmd_len++;
	
	/* response code */
	recv_param[cmd_len] = FELICA_RES_AUTHENTICATE_FELICA;
	cmd_len++;
	
	/* result_code */
	recv_param[cmd_len] = result_code;
	cmd_len++;
	
	memcpy( recv_buf, &recv_param, cmd_len );
	*recv_len = cmd_len;
	
	return ret;
}

int libnfc_tf_write_felica(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *t_val)
{
	return NFC_TF_SUCCESS;
}

int libnfc_tf_read_felica(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *t_val)
{
	libnfc_tf_SendCmd_t tf_cmd;
	uint8_t *cmd_buf, recv_param[NFC_TF_CMD_PKT_MAX];
	uint32_t cmd_len, data_length;
	int media_handle, ret;
	
	ALOGD( "%s", __FUNCTION__ );
	
	media_handle = libnfc_tf_get_media_handle_taginfo( tag );
	if ( media_handle <= 0 ){
		return NFC_TF_ERR;
	}
	
	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	cmd_buf = &tf_cmd.s_buffer[0];
	
	/* header, command, length */
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	libnfc_tf_set_com_header( cmd_buf, NFC_TF_CMD_COM_READ_FELICA, NFC_TF_READ_FELICA_SEND_PARAM_LENGTH );
	
	/* handle number */
	cmd_buf[cmd_len] = (uint8_t)(media_handle & 0xff);
	cmd_len++;
	
	/* block type */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_BLOCK_TYPE_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_TYPE_LENGTH );
	cmd_len += NFC_TF_BLOCK_TYPE_LENGTH;
	
	/* block number */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_BLOCK_NUMBER_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_NUMBER_LENGTH );
	cmd_len += NFC_TF_BLOCK_NUMBER_LENGTH;
	
	/* block count */
	memcpy( &cmd_buf[cmd_len], &send_buf[NFC_TF_READ_BLOCK_COUNT_REQ_ARRAY_NUMBER], NFC_TF_BLOCK_COUNT_LENGTH );
	cmd_len += NFC_TF_BLOCK_COUNT_LENGTH;
	
	/* bcc */
	libnfc_tf_insert_bcc( cmd_buf, cmd_len );
	cmd_len++;

	tf_cmd.s_length = cmd_len;
	cmd_len = 0;

// RICOH MOD-S G2 Porting
	ret = libnfc_tf_send_command_timeout( &tf_cmd, t_val );
	//ret = libnfc_tf_send_command_timeout( &tf_cmd, &t_val );
// RICOH MOD-E G2 Porting

	if ( ret != NFC_TF_SUCCESS ){
		return ret;
	}
	
	memset( recv_param, 0, sizeof(recv_param) );
	
	/* length */
	recv_param[cmd_len] = tf_cmd.r_length - 3;/* ( header + result + length[2] + bcc ) - ( commandCode + length[1] ) = 3 */
	cmd_len++;
	
	/* response code */
	recv_param[cmd_len] = FELICA_RES_READ_FELICA;
	cmd_len++;
	
	/* media status1 */
	recv_param[cmd_len] = tf_cmd.r_buffer[NFC_TF_READ_MEDIA_STATUS_1_RES_ARRAY_NUMBER];
	cmd_len++;
	
	/* media status2 */
	recv_param[cmd_len] = tf_cmd.r_buffer[NFC_TF_READ_MEDIA_STATUS_2_RES_ARRAY_NUMBER];
	cmd_len++;
	
	/* data */
	data_length = tf_cmd.r_buffer[NFC_TF_LENGTH_RES_ARRAY_NUMBER] - ( NFC_TF_MRDIA_STATUS1_LENGTH + NFC_TF_MRDIA_STATUS2_LENGTH );
	memcpy( &recv_param[cmd_len], &tf_cmd.r_buffer[NFC_TF_READ_DATA_RES_ARRAY_NUMBER], data_length );
	cmd_len += data_length;
	
	memcpy( recv_buf, &recv_param, cmd_len );
	*recv_len = cmd_len;

	return ret;
}
// RICOH ADD-E Felica Security Access

// RICOH ADD-S NDEF Detection Settings
int libnfc_TF_Change_FindMedia_Config( int configType, int configValue )
{
	ALOGD( "%s", __FUNCTION__ );
	return libnfc_tf_change_findmedia_config( configType, configValue );
}
// RICOH ADD-E NDEF Detection Settings

