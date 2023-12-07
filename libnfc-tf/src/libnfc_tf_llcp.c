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
#include <string.h>
#include <stdlib.h>
// RICOH ADD-E G2 Porting

#include "libnfc_tf.h"
#include "libnfc_tf_local.h"

#define NFC_TF_SOCKET_MGR_MAX           16
// RICOH CHG-S Porting No.3740 2016/12/20
//#define NFC_TF_LLCP_CONNECT_RETRY	20
#define NFC_TF_LLCP_CONNECT_RETRY	5
// RICOH CHG-E Porting No.3740 2016/12/20
#define NFC_TF_LLCP_DISCONNECT_RETRY	10
#define NFC_TF_CLOSEMEDIA_RETRY		10
#define NFC_TF_LLCP_TIMEOUT_VALUE	1500 // 1500msec
#define NFC_TF_CLOSEMEDIA_TIMEOUT_VALUE	1000 // 1000msec
#define NFC_TF_LLCP_WAIT		110000 // 110msec

enum {
	NFC_TF_LLCP_IDLE,
	NFC_TF_LLCP_CLOSED,
	NFC_TF_LLCP_LISTENING,
	NFC_TF_LLCP_CONNECTING,
	NFC_TF_LLCP_ESTABLISHED,
};

static int glibnfc_tf_llcp_state = NFC_TF_LLCP_IDLE;
static int glibnfc_tf_llcp_media_handle = 0;

static libnfc_tf_SendCmd_t              gNfcLlcpCmdBuf;
static libnfc_tf_llcp_socket_t         gLlcpSocket[NFC_TF_SOCKET_MGR_MAX];
static pthread_mutex_t gNfcLlcpMutex = PTHREAD_MUTEX_INITIALIZER;

static libnfc_tf_llcp_socket_t* libnfc_tf_llcp_alloc_socket( void )
{
	int i;
	libnfc_tf_llcp_socket_t* sock =  NULL;

	for ( i = 0; i < NFC_TF_SOCKET_MGR_MAX; i++ ){
		if ( gLlcpSocket[i].status == NFC_TF_LLCP_SOCK_STAT_NONE ){
			sock = &gLlcpSocket[i];
			break;
		}
	}

	return sock;
}

static int libnfc_tf_llcp_disconnect_process( libnfc_tf_llcp_socket_t *sock )
{
	uint8_t sap_handle;
	int ret;

	sap_handle = sock->sap_handle;

	ret = libnfc_tf_llcp_disconnect_retry( sap_handle );
	if ( ret != NFC_TF_SUCCESS ) {
		return NFC_TF_ERR_RESPONSE;
	}

	glibnfc_tf_llcp_state = NFC_TF_LLCP_IDLE;

	#ifdef NFC_TF_DEBUG
		ALOGE("%s: state=%d", __FUNCTION__, glibnfc_tf_llcp_state );
	#endif

	return NFC_TF_SUCCESS;
}

int libnfc_tf_llcp_disconnect_retry(uint8_t sap_handle)
{
	int retry;
	int ret;
        int timeout = NFC_TF_LLCP_TIMEOUT_VALUE;
        struct timeval t_val;
        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = (timeout % 1000) * 1000;

	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
        libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_DESTROY_LLCPSAP, &sap_handle, 1 );
        ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );

        if ( ret != NFC_TF_SUCCESS ){
                for ( retry = 0; retry < NFC_TF_LLCP_DISCONNECT_RETRY; retry++ ){
// RICOH CHG-S Porting No.3741 2016/12/20
                    //usleep( 100000 );
                    //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
                    usleep(10000);
                    ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3741 2016/12/20
                    if ( ret == NFC_TF_SUCCESS ){
                        break;
                    }
                }
                if ( retry >= NFC_TF_LLCP_DISCONNECT_RETRY ){
                        return NFC_TF_ERR_RESPONSE;
                }
        }
	return NFC_TF_SUCCESS;
}

static int libnfc_tf_llcp_accept_process( libnfc_tf_llcp_socket_t *sock, int media_handle )
{
	int retry;
	int ret;
	uint32_t param_len;
	uint8_t mhandle;
	uint8_t sap_handle;
	uint8_t connect_param[36];
	int timeout = NFC_TF_LLCP_TIMEOUT_VALUE;
	struct timeval t_val;
	t_val.tv_sec = timeout / 1000 + 1;
	t_val.tv_usec = ( timeout % 1000 ) * 1000;

	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_IDLE ){
		return NFC_TF_ERR_BUSY;
	}
	
	mhandle = (uint8_t)media_handle;

	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_CREATE_LLCPSAP, &mhandle, 1 );
// RICOH CHG-S Porting No.3742 2016/12/20
        //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val);
// RICOH CHG-E Porting No.3742 2016/12/20
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR_RESPONSE;
	}

	sap_handle = gNfcLlcpCmdBuf.r_buffer[4];

	memset( connect_param, 0, sizeof(connect_param) );
	connect_param[0] = sap_handle;
	connect_param[1] = sock->ssap_number;
	if ( sock->sap_name_length > 0 ){
		connect_param[2] = sock->sap_name_length;
		memcpy( &connect_param[3], sock->sap_name, sock->sap_name_length );
		param_len = 3 + sock->sap_name_length;
	}
	else{
		connect_param[2] = 0;
		param_len = 3;
	}
	
	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_LISTEN_LLCP, connect_param, param_len );
// RICOH CHG-S Porting No.3743 2016/12/20
        //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3743 2016/12/20
	if ( ret != NFC_TF_SUCCESS ){
		libnfc_tf_llcp_disconnect_retry( sap_handle );
		
		return NFC_TF_ERR_RESPONSE;
	}
	
	for ( retry = 0; retry < NFC_TF_LLCP_CONNECT_RETRY; retry++ ){
// RICOH DEL-S Porting No.3744 2016/12/20
		//usleep( 150000 );
// RICOH DEL-E Porting No.3744 2016/12/20
		memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
		libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_ACCEPT_LLCP, &sap_handle, 1 );
	        ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
		if ( ret == NFC_TF_SUCCESS ){
			break;
		}
		else{
			if ( gNfcLlcpCmdBuf.r_buffer[1] == NFC_TF_CMD_RESULT_LLCP_CONNECTING ){
#ifdef NFC_TF_DEBUG
				ALOGE("libnfc_tf_llcp_accept_process : retry=%d", retry+1 );
#endif
				continue;
			}

			libnfc_tf_llcp_disconnect_retry( sap_handle );

			return NFC_TF_ERR_RESPONSE;
		}
	}

	if ( retry >= NFC_TF_LLCP_CONNECT_RETRY ){
		libnfc_tf_llcp_disconnect_retry( sap_handle );
		
		return NFC_TF_ERR_NO_CONNECT;
	}
	
	sock->sap_handle = sap_handle;
	
	glibnfc_tf_llcp_state = NFC_TF_LLCP_ESTABLISHED;
#ifdef NFC_TF_DEBUG
        ALOGE("%s: state=%d", __FUNCTION__, glibnfc_tf_llcp_state );
#endif	

	return NFC_TF_SUCCESS;
}

static int libnfc_tf_llcp_connect_process( libnfc_tf_llcp_socket_t *sock, int media_handle )
{
	int retry;
	int ret;
	uint32_t param_len;
	uint8_t mhandle;
	uint8_t sap_handle;
	uint8_t connect_param[36];
        int timeout = NFC_TF_LLCP_TIMEOUT_VALUE;
        struct timeval t_val;
        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = ( timeout % 1000 ) * 1000;

	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_IDLE ){
		return NFC_TF_ERR_BUSY;
	}
	
	mhandle = (uint8_t)media_handle;

	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_CREATE_LLCPSAP, &mhandle, 1 );
// RICOH CHG-S Porting No.3745 2016/12/20
        //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3745 2016/12/20
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR_RESPONSE;
	}

	sap_handle = gNfcLlcpCmdBuf.r_buffer[4];

	memset( connect_param, 0, sizeof(connect_param) );
	connect_param[0] = sap_handle;
	connect_param[1] = sock->dsap_number;
	if ( sock->sap_name_length > 0 ){
		connect_param[2] = sock->sap_name_length;
		memcpy( &connect_param[3], sock->sap_name, sock->sap_name_length );
		param_len = 3 + sock->sap_name_length;
	}
	else{
		connect_param[2] = 0;
		param_len = 3;
	}

	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_CONNECT_LLCP, connect_param, param_len );
// RICOH CHG-S Porting No.3746 2016/12/20
		//ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3746 2016/12/20
	if ( ret != NFC_TF_SUCCESS ){
		for ( retry = 0; retry < NFC_TF_LLCP_CONNECT_RETRY; retry++ ){
// RICOH DEL-S Porting No.3746 2016/12/20
			//usleep( 150000 );
// RICOH DEL-E Porting No.3746 2016/12/20
			memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
			libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_ACCEPT_LLCP, &sap_handle, 1 );
		        ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
			if ( ret == NFC_TF_SUCCESS ){
				break;
			}
			else{
				if ( gNfcLlcpCmdBuf.r_buffer[1] == NFC_TF_CMD_RESULT_LLCP_CONNECTING ){
#ifdef NFC_TF_DEBUG
					ALOGE( "libnfc_tf_llcp_connect_process : retry=%d", retry+1 );
#endif
					continue;
				}

				libnfc_tf_llcp_disconnect_retry( sap_handle );
				return NFC_TF_ERR_RESPONSE;
			}
		}

		if ( retry >= NFC_TF_LLCP_CONNECT_RETRY ){
			libnfc_tf_llcp_disconnect_retry( sap_handle );
			return NFC_TF_ERR_NO_CONNECT;
		}
	}
	
	sock->sap_handle = sap_handle;
	
	glibnfc_tf_llcp_state = NFC_TF_LLCP_ESTABLISHED;
#ifdef NFC_TF_DEBUG
        ALOGE("%s: state=%d", __FUNCTION__, glibnfc_tf_llcp_state );
#endif
	
	return NFC_TF_SUCCESS;
}


int libnfc_tf_llcp_initialize( void )
{
	glibnfc_tf_llcp_state = NFC_TF_LLCP_IDLE;

	pthread_mutex_init( &gNfcLlcpMutex, NULL );

	memset( gLlcpSocket, 0, sizeof(gLlcpSocket) );

	return NFC_TF_SUCCESS;
}

libnfc_tf_llcp_socket_t* libnfc_tf_llcp_client_socket( int miu, int rw, int ssap  )
{
        libnfc_tf_llcp_socket_t* sock = NULL;

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	sock = libnfc_tf_llcp_alloc_socket();
	if ( sock != NULL ){
		sock->status = NFC_TF_LLCP_SOCK_STAT_CREATE;
		sock->socket_type = NFC_TF_LLCP_SOCK_TYPE_CLIENT;
		sock->ssap_number = ssap;
		sock->dsap_number = 0;
		sock->sap_name_length = 0;
		memset( sock->sap_name, 0, sizeof(sock->sap_name) );
		memset( &sock->accept_cb, 0, sizeof(libnfc_tf_llcp_accept_callback_t) );
		sock->server = NULL;
		sock->local_miu = miu;
		sock->remote_miu = NFC_TF_LLCP_MIU_DEFAULT;
		sock->local_rw = rw;
		sock->remote_rw = NFC_TF_LLCP_RW_DEFAULT;
	}
	
	pthread_mutex_unlock( &gNfcLlcpMutex );

        return sock;
}

libnfc_tf_llcp_socket_t* libnfc_tf_llcp_server_socket( int miu, int rw, int ssap, uint8_t *service_name )
{
	libnfc_tf_llcp_socket_t* sock = NULL;
	uint8_t sn_len = 0;

	if ( service_name != NULL ){
		sn_len = (uint8_t)strlen((char*)service_name);
		if ( sn_len > NFC_TF_LLCP_SERVICE_NAME_MAX_LENGTH ){
			return NULL;
		}
	}

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	sock = libnfc_tf_llcp_alloc_socket();
	if ( sock != NULL ){
		sock->status = NFC_TF_LLCP_SOCK_STAT_CREATE;
		sock->socket_type = NFC_TF_LLCP_SOCK_TYPE_SERVER;
		sock->ssap_number = ssap;
		sock->dsap_number = 0;
		sock->sap_name_length = sn_len;
		if ( service_name != NULL ){
			memcpy( sock->sap_name, service_name, sn_len );
			sock->sap_name[sn_len] = '\0';
		}
		else{
			memset( sock->sap_name, 0, sizeof(sock->sap_name) );
		}
		memset( &sock->accept_cb, 0, sizeof(libnfc_tf_llcp_accept_callback_t) );
		sock->server = NULL;
		sock->local_miu = miu;
		sock->remote_miu = NFC_TF_LLCP_MIU_DEFAULT;
		sock->local_rw = rw;
		sock->remote_rw = NFC_TF_LLCP_RW_DEFAULT;
	}

	pthread_mutex_unlock( &gNfcLlcpMutex );
	
        return sock;
}

int libnfc_tf_llcp_accept( libnfc_tf_llcp_socket_t *sock, int miu, int rw, pNfcTagLlcpAcceptCallback_t cb_func, void* pdata )
{
	if ( sock == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	if ( (sock->status == NFC_TF_LLCP_SOCK_STAT_NONE) ||
	     (sock->socket_type != NFC_TF_LLCP_SOCK_TYPE_SERVER)){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	if ( sock->status == NFC_TF_LLCP_SOCK_STAT_CREATE ){
		sock->status = NFC_TF_LLCP_SOCK_STAT_ACCEPT;
	}
	sock->local_miu = miu;
	sock->local_rw = rw;
	sock->accept_cb.callback = cb_func;
	sock->accept_cb.pdata = pdata;

	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return NFC_TF_SUCCESS;
}

int libnfc_tf_llcp_connect( libnfc_tf_llcp_socket_t *sock )
{
	int ret;
	int media_index = 0;
	
	if ( sock == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}
	
	if ( sock->socket_type != NFC_TF_LLCP_SOCK_TYPE_CLIENT ){
		return NFC_TF_ERR_INVALID_PARAM;
	}
	
	if ( sock->status != NFC_TF_LLCP_SOCK_STAT_CREATE ){
		return NFC_TF_ERR_BUSY;
	}
	
	pthread_mutex_lock( &gNfcLlcpMutex );

	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_IDLE ){
		pthread_mutex_unlock( &gNfcLlcpMutex );
		return NFC_TF_ERR_BUSY;
	}

	glibnfc_tf_llcp_media_handle = 0;
	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_OPENMEDIA, (uint8_t*)&media_index, 1 );
	ret = libnfc_tf_send_command( &gNfcLlcpCmdBuf );
	if ( ret != NFC_TF_SUCCESS ){
		pthread_mutex_unlock( &gNfcLlcpMutex );
		return NFC_TF_ERR;
	}

	glibnfc_tf_llcp_media_handle = (int)gNfcLlcpCmdBuf.r_buffer[4];

	ret = libnfc_tf_llcp_connect_process( sock, glibnfc_tf_llcp_media_handle );
	if ( ret == NFC_TF_SUCCESS ){
		sock->status = NFC_TF_LLCP_SOCK_STAT_ESTABLISH;
	}
	else{
		libnfc_tf_closemedia_retry(glibnfc_tf_llcp_media_handle);
		glibnfc_tf_llcp_media_handle = 0;
	}
	
	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return ret;
}

int libnfc_tf_llcp_send( libnfc_tf_llcp_socket_t *sock, uint8_t *buff, uint32_t len  )
{
	int ret;
	uint8_t *cmd_buf;
	uint8_t cmd_len = 0;
        int timeout = NFC_TF_LLCP_TIMEOUT_VALUE;
        struct timeval t_val;
        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = ( timeout % 1000 ) * 1000;
	
	if ( sock == NULL || buff == NULL || len > NFC_TF_LLCP_DATA_MAX_LENGTH ){
		return NFC_TF_ERR_INVALID_PARAM;
	}
	
	if ( sock->status != NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
		return NFC_TF_ERR_ABORT;
	}

	pthread_mutex_lock( &gNfcLlcpMutex );

	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_ESTABLISHED ){
		return NFC_TF_ERR_ABORT;
	}
	
	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	
	libnfc_tf_set_com_header( &gNfcLlcpCmdBuf.s_buffer[0], NFC_TF_CMD_COM_WRITE_LLCP, len + 3 );
	
	cmd_len = NFC_TF_CMD_HEADER_LENGTH;
	cmd_buf = &gNfcLlcpCmdBuf.s_buffer[0];
	
	cmd_buf[cmd_len] = sock->sap_handle;
	cmd_len++;
	cmd_buf[cmd_len] = (uint8_t)(len & 0xff);
	cmd_len++;
	cmd_buf[cmd_len] = (uint8_t)((len >> 8) & 0xff);
	cmd_len++;
	memcpy( &cmd_buf[cmd_len], buff, len);
	cmd_len += len;
	
	libnfc_tf_insert_bcc( &gNfcLlcpCmdBuf.s_buffer[0], cmd_len );
	gNfcLlcpCmdBuf.s_length = cmd_len + 1;
// RICOH CHG-S Porting No.3747 2016/12/20
        //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3747 2016/12/20
	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return ret;
}

int libnfc_tf_llcp_recv( libnfc_tf_llcp_socket_t *sock, uint8_t *buff, uint32_t buff_len )
{
	int ret;
	uint32_t data_len;
	uint8_t prm_buf[3];
        int timeout = NFC_TF_LLCP_TIMEOUT_VALUE;
        struct timeval t_val;
        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = ( timeout % 1000 ) * 1000;
	
	if ( sock == NULL || buff == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}
	
	if ( sock->status != NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
		return NFC_TF_ERR_ABORT;
	}

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_ESTABLISHED ){
		return NFC_TF_ERR_ABORT;
	}
	
	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	
	prm_buf[0] = sock->sap_handle;
	prm_buf[1] = (uint8_t)(buff_len & 0xff);
	prm_buf[2] = (uint8_t)((buff_len >> 8) & 0xff);
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_READ_LLCP, prm_buf, 3 );
// RICOH CHG-S Porting No.3748 2016/12/20
        //ret = libnfc_tf_send_command_timeout_and_wait( &gNfcLlcpCmdBuf, &t_val, NFC_TF_LLCP_WAIT );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
// RICOH CHG-E Porting No.3748 2016/12/20
	if ( ret != NFC_TF_SUCCESS ){
		pthread_mutex_unlock( &gNfcLlcpMutex );
		return -1;
	}
	
	data_len = gNfcLlcpCmdBuf.r_buffer[5];
	data_len = gNfcLlcpCmdBuf.r_buffer[4] + (data_len << 8);
	if ( data_len >= 1 ){
		memcpy( buff, &gNfcLlcpCmdBuf.r_buffer[6], data_len );
	}
	
	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return (int)data_len;
}

int libnfc_tf_llcp_close( libnfc_tf_llcp_socket_t *sock )
{
	libnfc_tf_llcp_socket_t* server;
	int stype;
	int status;
	int close_media_flg = 0;

	if ( sock == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	status = sock->status;
	if ( status == NFC_TF_LLCP_SOCK_STAT_NONE ){
		return NFC_TF_SUCCESS;
	}

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	stype = sock->socket_type;
	switch( stype ){
		case NFC_TF_LLCP_SOCK_TYPE_CLIENT:
			if ( status == NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
				libnfc_tf_llcp_disconnect_process( sock );
				close_media_flg = 1;
			}
			break;

		case NFC_TF_LLCP_SOCK_TYPE_SERVER:
			if ( status == NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
				libnfc_tf_llcp_disconnect_process( sock );
				close_media_flg = 1;
			}
			if ( sock->accept_cb.callback != NULL ){
				(*sock->accept_cb.callback)( (void*)sock, sock->accept_cb.pdata, NFC_TF_ERR_ABORT );
			}
			break;

		case NFC_TF_LLCP_SOCK_TYPE_SERVER_ACCEPT:
			if ( status == NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
				server = (libnfc_tf_llcp_socket_t*)sock->server;
				if ( server != NULL ){
					if ( server->status == NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
						libnfc_tf_llcp_disconnect_process( server );
						server->status = NFC_TF_LLCP_SOCK_STAT_ACCEPT;
						close_media_flg = 1;
					}
				}
			}
			break;

		default:
			break;
	}

	sock->status = NFC_TF_LLCP_SOCK_STAT_NONE;
	sock->socket_type = NFC_TF_LLCP_SOCK_TYPE_NONE;
	sock->sap_handle = 0;

	if ( close_media_flg != 0 ){
		libnfc_tf_closemedia_retry(glibnfc_tf_llcp_media_handle);
		glibnfc_tf_llcp_media_handle = 0;
	}

	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return NFC_TF_SUCCESS;
}

int libnfc_tf_llcp_aceept_polling( void )
{
	int i;
	int ret;
	int status = NFC_TF_SUCCESS;
	int media_index = 0;
	libnfc_tf_llcp_socket_t *sock = NULL;

	pthread_mutex_lock( &gNfcLlcpMutex );

	if ( glibnfc_tf_llcp_state != NFC_TF_LLCP_IDLE ){
		pthread_mutex_unlock( &gNfcLlcpMutex );
		return NFC_TF_ERR_BUSY;
	}

	glibnfc_tf_llcp_media_handle = 0;

	memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
	libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_OPENMEDIA, (uint8_t*)&media_index, 1 );
        ret = libnfc_tf_send_command( &gNfcLlcpCmdBuf );
        if ( ret == NFC_TF_SUCCESS ){
		glibnfc_tf_llcp_media_handle = (int)gNfcLlcpCmdBuf.r_buffer[4];
        }
	else{
		status = NFC_TF_ERR;
	}
	
	if ( glibnfc_tf_llcp_media_handle > 0 ){
		for ( i = 0; i < NFC_TF_SOCKET_MGR_MAX; i++ ){
			if ( (gLlcpSocket[i].socket_type == NFC_TF_LLCP_SOCK_TYPE_SERVER) &&
			     (gLlcpSocket[i].status == NFC_TF_LLCP_SOCK_STAT_ACCEPT) ){

				ret = libnfc_tf_llcp_accept_process( &gLlcpSocket[i], glibnfc_tf_llcp_media_handle );
				if ( ret == NFC_TF_SUCCESS ){
					sock = libnfc_tf_llcp_alloc_socket();
					if ( sock != NULL ){
						gLlcpSocket[i].status = NFC_TF_LLCP_SOCK_STAT_ESTABLISH;

						sock->status = NFC_TF_LLCP_SOCK_STAT_ESTABLISH;
						sock->socket_type = NFC_TF_LLCP_SOCK_TYPE_SERVER_ACCEPT;
						sock->sap_handle = gLlcpSocket[i].sap_handle;
						sock->ssap_number = gLlcpSocket[i].ssap_number;
						sock->dsap_number = gLlcpSocket[i].dsap_number;
						sock->sap_name_length = 0;
						sock->server = (void*)&gLlcpSocket[i];
						sock->local_miu = gLlcpSocket[i].local_miu;
						sock->remote_miu = gLlcpSocket[i].remote_miu;
						sock->local_rw = gLlcpSocket[i].local_rw;
						sock->remote_rw = gLlcpSocket[i].remote_rw;

						if ( gLlcpSocket[i].accept_cb.callback != NULL ){
							(*gLlcpSocket[i].accept_cb.callback)( (void*)sock, gLlcpSocket[i].accept_cb.pdata, NFC_TF_SUCCESS );
						}
					}
					break;
				}
			}
		}
	}

	if ( glibnfc_tf_llcp_media_handle > 0 && ( sock == NULL )){
		libnfc_tf_closemedia_retry(glibnfc_tf_llcp_media_handle);
		glibnfc_tf_llcp_media_handle = 0;
	}

	pthread_mutex_unlock( &gNfcLlcpMutex );
	
	return status;
}

void libnfc_tf_llcp_tag_lost( void )
{
	int i;

	pthread_mutex_lock( &gNfcLlcpMutex );
	
	for ( i = 0; i < NFC_TF_SOCKET_MGR_MAX; i++ ){
		if ( gLlcpSocket[i].status == NFC_TF_LLCP_SOCK_STAT_ESTABLISH ){
			switch ( gLlcpSocket[i].socket_type ){
				case NFC_TF_LLCP_SOCK_TYPE_SERVER:
					gLlcpSocket[i].status = NFC_TF_LLCP_SOCK_STAT_ACCEPT;
					break;

				case NFC_TF_LLCP_SOCK_TYPE_CLIENT:
					gLlcpSocket[i].status = NFC_TF_LLCP_SOCK_STAT_CREATE;
					break;

				case NFC_TF_LLCP_SOCK_TYPE_SERVER_ACCEPT:
				default:
					gLlcpSocket[i].status = NFC_TF_LLCP_SOCK_STAT_NONE;
					gLlcpSocket[i].socket_type = NFC_TF_LLCP_SOCK_TYPE_NONE;
					gLlcpSocket[i].sap_handle = 0;
					break;
			}
		}
	}

	glibnfc_tf_llcp_state = NFC_TF_LLCP_IDLE;
#ifdef NFC_TF_DEBUG
        ALOGE("%s: state=%d", __FUNCTION__, glibnfc_tf_llcp_state );
#endif

	pthread_mutex_unlock( &gNfcLlcpMutex );
	
}

int libnfc_tf_closemedia_retry(int media_handle)
{
	int retry;
	int ret;
	int timeout = NFC_TF_CLOSEMEDIA_TIMEOUT_VALUE;
        struct timeval t_val;
        t_val.tv_sec = timeout / 1000 + 1;
        t_val.tv_usec = (timeout % 1000) * 1000;

        memset( &gNfcLlcpCmdBuf, 0, sizeof(gNfcLlcpCmdBuf) );
        libnfc_tf_command_set( &gNfcLlcpCmdBuf, NFC_TF_CMD_COM_CLOSEMEDIA, (uint8_t*)&media_handle, 1 );
        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );

        if ( ret != NFC_TF_SUCCESS ){
                for ( retry = 0; retry < NFC_TF_CLOSEMEDIA_RETRY; retry++ ){
                        usleep( 100000 );
                        ret = libnfc_tf_send_command_timeout( &gNfcLlcpCmdBuf, &t_val );
                        if ( ret == NFC_TF_SUCCESS ){
                                break;
                        }
                }
                if ( retry >= NFC_TF_CLOSEMEDIA_RETRY ){
                        return NFC_TF_ERR_RESPONSE;
                }
        }
        return NFC_TF_SUCCESS;
}

