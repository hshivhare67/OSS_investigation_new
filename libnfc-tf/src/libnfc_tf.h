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

#ifndef LIBNFC_TF_H
#define LIBNFC_TF_H

#include <sys/types.h>

#include <libnfc_tf_if.h>

// RICOH ADD-S G2 Porting
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "libnfc_tf"
#endif
//#define LOG_TAG "libnfc_tf"
// RICOH ADD-E G2 Porting

#include <utils/Log.h>

typedef struct {
	uint8_t *data;
	uint32_t len;
} libnfc_tf_detect_data_raw_t;


typedef void (*libnfc_tf_nfc_detect_callback_t)(void*);
typedef void (*libnfc_tf_nfc_taglost_callback_t)(void*);
typedef void (*libnfc_tf_nfc_reset_callback_t)(void);


extern int libnfc_tf_initialize( void );
extern int libnfc_tf_deinitialize( void );
extern int libnfc_tf_open( void );
extern int libnfc_tf_open_recognition( int params_enc );
extern int libnfc_tf_close( void );
extern void libnfc_tf_secure_change_close( void );
extern int libnfc_tf_get_query_state( void );
extern int libnfc_tf_nfc_polling_start( libnfc_tf_FindMediaConfig_t *config );
extern int libnfc_tf_nfc_polling_stop( void );
extern void libnfc_tf_nfc_restart_polling( void );
extern int libnfc_tf_nfc_connect( libnfc_tf_TagInfo_t *tag );
extern int libnfc_tf_nfc_disconnect( libnfc_tf_TagInfo_t *tag );
extern void libnfc_tf_register_highlayer_detect_callback( pNfcTagDetectRespCallback_t cb_func, void* pdata );
extern void libnfc_tf_register_highlayer_lost_callback( pNfcTagDetectRespCallback_t cb_func, void* pdata );
extern void libnfc_tf_register_highlayer_reset_callback(pNfcTagDetectRespCallback_t cb_func, void* pdata);


extern int libnfc_tf_get_id( libnfc_tf_TagInfo_t *tag, uint8_t *o_id, uint32_t *o_len );
extern int libnfc_tf_get_media_handle_id( uint8_t *id, uint32_t id_len );
extern int libnfc_tf_get_media_handle_taginfo( libnfc_tf_TagInfo_t *tag );

extern uint8_t libnfc_tf_get_bcc( uint8_t *buf, uint32_t len );
extern void libnfc_tf_insert_bcc( uint8_t *buf, uint32_t len );
extern void libnfc_tf_set_com_header( uint8_t *buf, uint8_t cmd, uint32_t param_len );
extern void libnfc_tf_command_set( libnfc_tf_SendCmd_t *tf_cmd, uint8_t cmd, uint8_t *param_buf, uint32_t param_len );
extern int libnfc_tf_send_command( libnfc_tf_SendCmd_t *tf_cmd );
extern int libnfc_tf_send_command_timeout_and_wait( libnfc_tf_SendCmd_t *tf_cmd, struct timeval *timeout_val, int usec );
extern int libnfc_tf_send_command_timeout( libnfc_tf_SendCmd_t *tf_cmd, struct timeval *timeout_val );


extern void libnfc_tf_poll_register_detect_callback(libnfc_tf_nfc_detect_callback_t cb_addr);
extern void libnfc_tf_poll_register_taglost_callback(libnfc_tf_nfc_taglost_callback_t cb_addr);
extern void libnfc_tf_poll_register_reset_callback(libnfc_tf_nfc_reset_callback_t cb_addr);
extern void libnfc_tf_poll_stop( void );
extern void libnfc_tf_set_default_findmedia_config( void );
extern void libnfc_tf_set_findmedia_config( libnfc_tf_FindMediaConfig_t *config );
extern void* libnfc_tf_poll_thread( void *arg );
extern void libnfc_tf_poll_repolling( void );
extern void libnfc_tf_poll_p2p_start( void );
extern void libnfc_tf_poll_p2p_stop( void );


typedef struct {
        pNfcTagLlcpAcceptCallback_t     callback;
        void*                           pdata;
} libnfc_tf_llcp_accept_callback_t;

typedef struct {
        int                             status;
        int                             socket_type;
        uint8_t                         sap_handle;
        uint8_t                         ssap_number;
        uint8_t                         dsap_number;
        uint8_t                         sap_name_length;
        uint8_t                         sap_name[NFC_TF_LLCP_SERVICE_NAME_MAX_LENGTH+1];
        libnfc_tf_llcp_accept_callback_t        accept_cb;
        void*                           *server;

        uint16_t                        local_miu;
        uint16_t                        remote_miu;
        uint8_t                         local_rw;
        uint8_t                         remote_rw;
} libnfc_tf_llcp_socket_t;

extern int libnfc_tf_llcp_initialize( void );
extern libnfc_tf_llcp_socket_t* libnfc_tf_llcp_client_socket( int miu, int rw, int ssap  );
extern libnfc_tf_llcp_socket_t* libnfc_tf_llcp_server_socket( int miu, int rw, int ssap, uint8_t *service_name );
extern int libnfc_tf_llcp_accept( libnfc_tf_llcp_socket_t *sock, int miu, int rw, pNfcTagLlcpAcceptCallback_t cb_func, void* pdata );
extern int libnfc_tf_llcp_connect( libnfc_tf_llcp_socket_t *sock );
extern int libnfc_tf_llcp_send( libnfc_tf_llcp_socket_t *sock, uint8_t *buff, uint32_t len  );
extern int libnfc_tf_llcp_recv( libnfc_tf_llcp_socket_t *sock, uint8_t *buff, uint32_t buff_len );
extern int libnfc_tf_llcp_close( libnfc_tf_llcp_socket_t *sock );
extern int libnfc_tf_llcp_aceept_polling( void );
extern void libnfc_tf_llcp_tag_lost( void );
extern int libnfc_tf_llcp_disconnect_retry(uint8_t sap_handle);
extern int libnfc_tf_closemedia_retry(int media_handle);

extern int libnfc_tf_secure_get_mode( void );
extern void libnfc_tf_secure_get_hostcode( uint8_t* host_challenge_key, uint8_t* host_code );
extern void libnfc_tf_secure_primary_encrypt( uint8_t* in, uint8_t* out, int len, int enc );
extern void libnfc_tf_secure_params_encrypt( uint8_t* in, uint8_t* out, int len, int enc );
extern int libnfc_tf_secure_initialize( int secure_mode, uint8_t *p_key, uint8_t *r_key );
extern int libnfc_tf_secure_params_encrypt_check( uint8_t command );
extern int libnfc_tf_secure_create_paramskey( uint8_t *challenge_key );
extern int libnfc_tf_secure_change_mode( int secure_mode );

// RICOH ADD-S Felica Security Access
extern int libnfc_tf_get_device_info( uint8_t *recv_buf, uint32_t *recv_len );

extern int libnfc_tf_write_felica_without_encryption( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *tval );
extern int libnfc_tf_read_felica_without_encryption( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *tval );
extern int libnfc_tf_authenticate_felica( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *tval );
extern int libnfc_tf_write_felica( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *tval );
extern int libnfc_tf_read_felica( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, struct timeval *tval );
extern int libnfc_tf_send_felica_access_command_set(libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, int timeout );

extern int libnfc_tf_set_felica_system_code(uint8_t *systemCode);
// RICOH ADD-E Felica Security Access

// RICOH ADD-S NDEF Detection Settings
int libnfc_tf_change_findmedia_config( int configType, int configValue );
// RICOH ADD-E NDEF Detection Settings
#endif

