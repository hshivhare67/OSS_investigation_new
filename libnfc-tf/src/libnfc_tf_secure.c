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

// RICOH ADD-S G2 Porting
#include <string.h>
#include <stdlib.h>
// RICOH ADD-E G2 Porting

#include <libnfc_tf_if.h>

#include "libnfc_tf.h"
#include "libnfc_tf_hal.h"
#include "libnfc_tf_local.h"

typedef struct {
	AES_KEY		enc_key;	/* encrypt key */
	AES_KEY		dec_key;	/* decrypt key */
} libnfc_tf_aes_key_t;

typedef struct {
	int			init_flag;
	int			params_flag;
	
	int			secure_mode;
	libnfc_tf_aes_key_t	primary_key;
	libnfc_tf_aes_key_t	params_key;
} libnfc_tf_secure_t;


#define NFC_TF_SECURE_ECB_KEY_LEN_BIT	128
#define NFC_TF_SECURE_ECB_KEY_LEN	(NFC_TF_SECURE_ECB_KEY_LEN_BIT/8)

static uint8_t gNfcSecurePrimaryKey[NFC_TF_SECURE_ECB_KEY_LEN] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
static uint8_t gNfcSecureRecognitionKey[NFC_TF_SECURE_ECB_KEY_LEN] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};

static libnfc_tf_secure_t gNfcSecure;

int libnfc_tf_secure_get_mode( void )
{
	return gNfcSecure.secure_mode;
}

static void libnfc_tf_secure_set_primary_key( uint8_t *key )
{
	memcpy( gNfcSecurePrimaryKey, key, NFC_TF_SECURE_ECB_KEY_LEN );
}

static void libnfc_tf_secure_set_recognition_key( uint8_t *key )
{
        memcpy( gNfcSecureRecognitionKey, key, NFC_TF_SECURE_ECB_KEY_LEN );
}

static uint8_t* libnfc_tf_secure_get_primarykey( void )
{
	return (uint8_t*)gNfcSecurePrimaryKey;
}

static uint8_t* libnfc_tf_secure_get_recognitionkey( void )
{
	return (uint8_t*)gNfcSecureRecognitionKey;
}

void libnfc_tf_secure_get_hostcode( uint8_t* host_challenge_key, uint8_t* host_code )
{
	AES_KEY aes_key;
	uint8_t *reco_key = libnfc_tf_secure_get_recognitionkey();

	AES_set_encrypt_key( reco_key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &aes_key );
	AES_ecb_encrypt( host_challenge_key, host_code, &aes_key, AES_ENCRYPT );
}

void libnfc_tf_secure_primary_encrypt( uint8_t* in, uint8_t* out, int len, int enc )
{
	AES_KEY *key;
	int cur = 0;

        if ( gNfcSecure.init_flag == 0 ){
                return;
        }

	if ( ( in == NULL ) || ( out == NULL ) ){
		return;
	}

	if ( ( len % 16 ) != 0 ){
		return;
	}

	key = ( enc == AES_ENCRYPT ) ? &gNfcSecure.primary_key.enc_key: &gNfcSecure.primary_key.dec_key;
	for ( cur = 0; cur < len; cur += 16 ){
		AES_ecb_encrypt( in + cur, out + cur, key, enc );
	}
}

void libnfc_tf_secure_params_encrypt( uint8_t* in, uint8_t* out, int len, int enc )
{
	AES_KEY *key;
	int cur = 0;

        if ( (gNfcSecure.init_flag == 0) ||
	     (gNfcSecure.params_flag == 0) ){
                return;
        }

	if ( ( in == NULL ) || ( out == NULL ) ){
		return;
	}

	if ( ( len % 16 ) != 0 ){
		return;
	}

	key = ( enc == AES_ENCRYPT ) ? &gNfcSecure.params_key.enc_key: &gNfcSecure.params_key.dec_key;
	for ( cur = 0; cur < len; cur += 16 ){
		AES_ecb_encrypt( in + cur, out + cur, key, enc );
	}
}

int libnfc_tf_secure_initialize( int secure_mode, uint8_t *p_key, uint8_t *r_key )
{
	uint8_t *key;

	memset( &gNfcSecure, 0, sizeof(gNfcSecure) );

#ifndef NFC_TF_DEBUG
	if ( p_key == NULL || r_key == NULL ){
		return NFC_TF_ERR_INVALID_PARAM;
	}
#endif

	gNfcSecure.init_flag = 1;
	gNfcSecure.params_flag = 0;
	gNfcSecure.secure_mode = secure_mode;

#ifdef NFC_TF_DEBUG
/*
	if ( p_key != NULL ){
		libnfc_tf_secure_set_primary_key( p_key );
	}

	if ( r_key != NULL ){
		libnfc_tf_secure_set_recognition_key( r_key );
	}
*/
#endif

	key = libnfc_tf_secure_get_primarykey();
	AES_set_encrypt_key( key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &gNfcSecure.primary_key.enc_key );
	AES_set_decrypt_key( key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &gNfcSecure.primary_key.dec_key );

#ifdef NFC_TF_DEBUG
	ALOGE( "%s : mode = %d\n", __FUNCTION__, secure_mode );
#endif

	return NFC_TF_SUCCESS;
}

int libnfc_tf_secure_params_encrypt_check( uint8_t command )
{
	int result = 0;

	switch ( command ){
		case NFC_TF_CMD_COM_OPEN:
		case NFC_TF_CMD_COM_CLOSE:
		case NFC_TF_CMD_COM_QUERYSTATE:
		case NFC_TF_CMD_COM_RECOVER:
		case NFC_TF_CMD_COM_PRIMARYKEY:
		case NFC_TF_CMD_COM_SETPRIMARYKEY:
		case NFC_TF_CMD_COM_COMPLETE_LOAD:
		case NFC_TF_CMD_COM_FREEMEDIA:
		case NFC_TF_CMD_COM_ENABLE_RECOGNITION:
		case NFC_TF_CMD_COM_DISABLE_RECOGNITION:
		case NFC_TF_CMD_COM_OPEN_RECOGNITION:
		case NFC_TF_CMD_COM_OPENSECURE_RECOGNITION:
		case NFC_TF_CMD_COM_REQUEST_RECOGNITION:
			result = 0;
			break;

		default:
			result = 1;
	}

	return result;
}

int libnfc_tf_secure_create_paramskey( uint8_t *challenge_key )
{
	uint8_t params_key[16];

	libnfc_tf_secure_primary_encrypt( challenge_key, params_key, 16, AES_ENCRYPT );

	AES_set_encrypt_key( params_key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &gNfcSecure.params_key.enc_key );
	AES_set_decrypt_key( params_key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &gNfcSecure.params_key.dec_key );

	gNfcSecure.params_flag = 1;

	return NFC_TF_SUCCESS;
}

static int libnfc_tf_secure_enable_recognition( void )
{
	libnfc_tf_SendCmd_t tf_cmd;
	uint8_t challenge_key[16];
	uint8_t *primary_key = NULL;
	uint8_t primary_key_enc[16];		/* encrypted primarykey */
	uint8_t *recognition_key = NULL;
	uint8_t recognition_key_enc[16];	/* encrypted recognitionkey */
	AES_KEY aes_key;
	int ret;

        if ( gNfcSecure.init_flag == 0 ){
                return NFC_TF_ERR;
        }

	memset( challenge_key, 0, sizeof(challenge_key) );
	libnfc_tf_hal_get_random( challenge_key, sizeof(challenge_key) );

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_PRIMARYKEY, challenge_key, sizeof(challenge_key) );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR;
	}

	primary_key = libnfc_tf_secure_get_primarykey();
        AES_set_encrypt_key( challenge_key, NFC_TF_SECURE_ECB_KEY_LEN_BIT, &aes_key );
        AES_ecb_encrypt( primary_key, primary_key_enc, &aes_key, AES_ENCRYPT );

	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_SETPRIMARYKEY, primary_key_enc, sizeof(primary_key_enc) );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR;
	}

	recognition_key = libnfc_tf_secure_get_recognitionkey();
	libnfc_tf_secure_primary_encrypt( recognition_key, recognition_key_enc, sizeof(recognition_key_enc), AES_ENCRYPT );
	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_ENABLE_RECOGNITION, recognition_key_enc, sizeof(recognition_key_enc) );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR;
	}

	return NFC_TF_SUCCESS;
}

static int libnfc_tf_secure_disable_recognition( void )
{
	libnfc_tf_SendCmd_t tf_cmd;
	uint8_t *recognition_key;
	uint8_t recognition_key_enc[16];        /* encrypted recognitionkey */
	int ret;

        if ( gNfcSecure.init_flag == 0 ){
                return NFC_TF_ERR;
        }

	recognition_key = libnfc_tf_secure_get_recognitionkey();
	libnfc_tf_secure_primary_encrypt( recognition_key, recognition_key_enc, sizeof(recognition_key_enc), AES_ENCRYPT );
	memset( &tf_cmd, 0, sizeof(libnfc_tf_SendCmd_t) );
	libnfc_tf_command_set( &tf_cmd, NFC_TF_CMD_COM_DISABLE_RECOGNITION, recognition_key_enc, sizeof(recognition_key_enc) );
	ret = libnfc_tf_send_command( &tf_cmd );
	if ( ret != NFC_TF_SUCCESS ){
		return NFC_TF_ERR;
	}

	return NFC_TF_SUCCESS;
}

int libnfc_tf_secure_change_mode( int secure_mode )
{
	int ret;
	int query_state;

	if ( gNfcSecure.init_flag == 0 ){
		return NFC_TF_ERR;
	}

	if ( (secure_mode != NFC_TF_SECURE_MODE_NONE) &&
	     (secure_mode != NFC_TF_SECURE_MODE_RECOGNITION) &&
	     (secure_mode != NFC_TF_SECURE_MODE_SECURE_HOST) ){
		return NFC_TF_ERR_INVALID_PARAM;
	}

	query_state = libnfc_tf_get_query_state();
	if ( query_state != NFC_TF_QUERYSTATE_IDLING ){
		return NFC_TF_ERR_BUSY;
	}

	if ( secure_mode == NFC_TF_SECURE_MODE_NONE ){
		ret = libnfc_tf_secure_disable_recognition();
		if ( ret != NFC_TF_SUCCESS ){
			return NFC_TF_ERR;
		}
	}
	else{
		ret = libnfc_tf_secure_enable_recognition();
		if ( ret != NFC_TF_SUCCESS ){
			return NFC_TF_ERR;
		}
	}

	gNfcSecure.secure_mode = secure_mode;

	libnfc_tf_secure_change_close();

	return NFC_TF_SUCCESS;

}



