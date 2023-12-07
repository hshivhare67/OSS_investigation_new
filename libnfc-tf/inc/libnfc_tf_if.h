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

#ifndef LIBNFC_TF_IF_H
#define LIBNFC_TF_IF_H

#include <sys/types.h>

#define NFC_TF_SUCCESS				0
#define NFC_TF_ERR					-1
#define NFC_TF_ERR_INVALID_PARAM	-2
#define NFC_TF_ERR_TIMEOUT			-3
#define NFC_TF_ERR_RESPONSE			-4
#define NFC_TF_ERR_BUSY				-5
#define NFC_TF_ERR_ABORT			-6
#define NFC_TF_ERR_NO_CONNECT			-7
#define NFC_TF_ERR_ENCRYPT			-8

#define NFC_TF_COM_THROUGH_TIMEOUT	500	/* no response timeout 500ms */
#define NFC_TF_UID_MAX_LENGTH		12
#define NFC_TF_CMD_PKT_MAX			501
#define NFC_TF_CMD_PKT_PARAM_MAX		496

#define NFC_TF_NDEF_CARD_INVALID		0
#define NFC_TF_NDEF_CARD_INITIALISED	1
#define NFC_TF_NDEF_CARD_READ_WRITE		2
#define NFC_TF_NDEF_CARD_READ_ONLY		3

typedef enum {
	NFC_TF_RFTYPE_NONE = 0,

	NFC_TF_RFTYPE_FELICA,
	NFC_TF_RFTYPE_ISO14443A,
	NFC_TF_RFTYPE_ISO14443B,
	NFC_TF_RFTYPE_ISO15693,
	NFC_TF_RFTYPE_P2PINITIATOR,

	NFC_TF_RFTYPE_MAXNUM
} libnfc_tf_RFType;

typedef enum {
	NFC_TF_MEDIA_OTHER = 0,
	NFC_TF_MEDIA_FELICA,
	NFC_TF_MEDIA_MOBILE_FELICA,
	NFC_TF_MEDIA_MIFARE,
	NFC_TF_MEDIA_JICSAP,
	NFC_TF_MEDIA_NDEF,
	NFC_TF_MEDIA_ICODESLI,
	NFC_TF_MEDIA_P2P_TAGERT,

	NFC_TF_MEDIA_MAX
} libnfc_tf_MediaType;

typedef struct {
	uint8_t	Uid[10];
	uint8_t	UidLength;
	uint8_t	AppData[48];
	uint8_t AppDataLength;
	uint8_t	Sak;
	uint8_t	AtqA[2];
	uint8_t	MaxDataRate;
	uint8_t	Fwi_Sfgt;
} libnfc_tf_TagInfo_Iso14443A;

typedef struct {
	uint8_t	AtqB[12];
	uint8_t	HiLayerResp[48];
	uint8_t	HiLayerRespLength;
	uint8_t	Afi;
	uint8_t	MaxDataRate;
} libnfc_tf_TagInfo_Iso14443B;

typedef struct {
	uint8_t	IDm[8];
	uint8_t	IDmLength;
	uint8_t	PMm[8];
	uint8_t SystemCode[2];
} libnfc_tf_TagInfo_Felica;

typedef struct {
	uint8_t	Uid[8];
	uint8_t	UidLength;
	uint8_t Dsfid;
	uint8_t	Flags;
	uint8_t	Afi;
} libnfc_tf_TagInfo_Iso15693;

typedef struct {
	uint8_t	NFCID[10];
	uint8_t	NFCID_Length;
	uint8_t	ATRInfo[48];
	uint8_t	ATRInfo_Length;
	uint8_t	SelRes;
	uint8_t	SenseRes[2];
	uint8_t	Nfcip_Active;
	uint8_t	MaxFrameLength;
	uint8_t	Nfcip_Datarate;
} libnfc_tf_TagInfo_P2p;

typedef union {
	libnfc_tf_TagInfo_Iso14443A	Iso14443A_Info;
	libnfc_tf_TagInfo_Iso14443B	Iso14443B_Info;
	libnfc_tf_TagInfo_Felica	Felica_Info;
	libnfc_tf_TagInfo_Iso15693	Iso15693_Info;
	libnfc_tf_TagInfo_P2p		P2p_Info;
} libnfc_tf_TagTypeDetail_t;

typedef struct {
	libnfc_tf_RFType		rf_type;
	libnfc_tf_MediaType		media_type;
	libnfc_tf_TagTypeDetail_t	tag_type;
} libnfc_tf_TagInfo_t;

typedef struct {
	int			info_num;
	libnfc_tf_TagInfo_t	info[NFC_TF_RFTYPE_MAXNUM];
} libnfc_tf_TagDetectInfo_t;

typedef struct {
	uint8_t		s_buffer[NFC_TF_CMD_PKT_MAX];
	uint32_t	s_length;
	uint8_t		r_buffer[NFC_TF_CMD_PKT_MAX];
	uint32_t	r_length;
} libnfc_tf_SendCmd_t;


typedef struct {
	uint8_t		holding;
	uint8_t		retry_limit;
	uint8_t		felica_setbit;		/* bit0:baudrate bit1:limit bit2:system code */
	uint8_t		felica_baudrate;	/* 0:212kpbs 1:424kbps */
	uint8_t		felica_limit;
	uint8_t		felica_systemcode[2];	/* felica system code (little endian) */
	uint8_t		iso14443a_setbit;	/* bit0:limit */
	uint8_t		iso14443a_limit;
	uint8_t		iso14443b_setbit;	/* bit0:limit bit1:afi */
	uint8_t		iso14443b_limit;
	uint8_t		iso14443b_afi;
	uint8_t		iso15693_setbit;	/* bit0:limit bit1:afi */
	uint8_t		iso15693_limit;
	uint8_t		iso15693_afi;
	uint8_t		p2p_setbit;			/* bit0:limit */
	uint8_t		p2p_limit;
} libnfc_tf_FindMediaConfig_t;

typedef struct {
	uint8_t		NdefCardState;
	uint32_t	ActualNdefMsgLength;
	uint32_t	MaxNdefMsgLength;
} libnfc_tf_ndef_info_t;


typedef void (*pNfcTagDetectRespCallback_t)( libnfc_tf_TagDetectInfo_t *taginfo, void* pdata );
typedef void (*pNfcTagLostRespCallback_t)( libnfc_tf_TagDetectInfo_t *taginfo, void* pdata );


extern int libnfc_TF_InitOpen( void );
extern int libnfc_TF_Open( void );
extern int libnfc_TF_Close( void );
// RICOH MOD-S Felica Security Access
//extern int libnfc_TF_Enable( pNfcTagDetectRespCallback_t cb_func, void* pdata );
extern int libnfc_TF_Enable( pNfcTagDetectRespCallback_t cb_func, void* pdata, uint8_t *systemCode );
// RICOH MOD-E Felica Security Access
extern int libnfc_TF_Disable( void );
extern int libnfc_TF_Connect( libnfc_tf_TagInfo_t *tag );
extern int libnfc_TF_Disconnect( libnfc_tf_TagInfo_t *tag );
extern int libnfc_TF_IsConnected( libnfc_tf_TagInfo_t *tag );
extern int libnfc_TF_SendCommand( libnfc_tf_SendCmd_t *cmd );
extern int libnfc_TF_TransceiveTimeout( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len, int timeout );
extern int libnfc_TF_Transceive( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len, uint8_t *recv_buf, uint32_t *recv_len );
extern int libnfc_TF_CheckNdef( libnfc_tf_TagInfo_t *tag, libnfc_tf_ndef_info_t *chkndef );
extern int libnfc_TF_PutNdefMessage( libnfc_tf_TagInfo_t *tag, uint8_t *send_buf, uint32_t send_len );
extern int libnfc_TF_GetNdefMessage( libnfc_tf_TagInfo_t *tag, uint8_t **o_buf_addr, uint32_t *recv_len );
extern int libnfc_TF_LostRespCbRegister(pNfcTagLostRespCallback_t cb_func, void* pdata);
extern int libnfc_TF_RestRespCbRegister(pNfcTagLostRespCallback_t cb_func, void* pdata);
extern int libnfc_TF_SetTransceiveTimeout( int timeout );
extern int libnfc_TF_ResetTransceiveTimeout( void );

#define NFC_TF_LLCP_SERVICE_NAME_MAX_LENGTH		32

typedef void (*pNfcTagLlcpAcceptCallback_t)( void* socket_handle, void* pdata, int status );
extern int libnfc_TF_LlcpAcceptRegister( void* socket_handle, pNfcTagLlcpAcceptCallback_t cb_func, void* pdata );

extern int libnfc_TF_Llcp_CreateServerSocket( int miu, int rw, int ssap, uint8_t *service_name, void** handle );
extern int libnfc_TF_Llcp_CreateClientSocket( int miu, int rw, int ssap, void** handle );
extern int libnfc_TF_Llcp_Accept( void* handle, int miu, int rw, pNfcTagLlcpAcceptCallback_t cb_func, void* pdata );
extern int libnfc_TF_Llcp_Connect( libnfc_tf_TagInfo_t* tag, void* handle, int dsap );
extern int libnfc_TF_Llcp_ConnectBy( libnfc_tf_TagInfo_t* tag, void* handle, uint8_t *service_name );
extern int libnfc_TF_Llcp_Close( void* handle );
extern int libnfc_TF_Llcp_Send( void* handle, uint8_t *buff, uint32_t len );
extern int libnfc_TF_Llcp_Recv( void* handle, uint8_t *buff, uint32_t buff_len );
extern int libnfc_TF_Llcp_GetRemoteSockMiu( void* handle );
extern int libnfc_TF_Llcp_GetRemoteSockRW( void* handle );


enum {
	NFC_TF_SECURE_MODE_NONE = 0,
	NFC_TF_SECURE_MODE_RECOGNITION,
	NFC_TF_SECURE_MODE_SECURE_HOST,
};

extern int libnfc_TF_InitSecureMode( int secure_mode, uint8_t *p_key, uint8_t *r_key );
extern int libnfc_TF_Change_SecureMode( int secure_mode );

extern int libnfc_TF_HW_FailCheck( int timeout_ms );

// RICOH ADD-S Felica Security Access
#define NFC_TF_COM_FELICA_ACCESS_COMMAND_TIMEOUT	6	/* no response timeout 5s */

typedef struct {
	uint8_t		device_code[16];
	uint8_t		device_version[10];
	uint8_t		device_serial[12];
	uint8_t		firm_id[8];
	uint8_t		firm_version[8];
} libnfc_tf_GetInformationResult_t;

typedef struct {
	int			felica_systemcode_search;
	uint8_t		felica_systemcode[2];
} libnfc_tf_SystemCodeConfig_t;

enum {
	NFC_TF_FELICA_SYSTEM_CODE_DISABLE = 0,
	NFC_TF_FELICA_SYSTEM_CODE_ENABLE,
};

enum {
	NFC_TF_ACCESS_MODE_COMMUNICATE_THROUGH = 0,
	NFC_TF_ACCESS_MODE_FELICA_DATA_ACCESS,
};

extern int libnfc_TF_Set_Felica_Access_Mode(int accessMode);
extern int libnfc_TF_Set_Felica_System_Code(uint8_t *systemCode);
extern int libnfc_TF_Get_Device_Info(uint8_t *recvbuf, uint32_t *recvlen);
// RICOH ADD-E Felica Security Access

// RICOH ADD-S NDEF Detection Settings
#define NFC_TF_FINDMEDIA_CONFIG_TYPE_NDEF_SETTINGS			1
#define NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_ENABLE	0
#define NFC_TF_FINDMEDIA_CONFIG_VALUE_NDEF_SETTINGS_DISABLE	1

extern int libnfc_TF_Change_FindMedia_Config(int configType, int configValue);
// RICOH ADD-E NDEF Detection Settings

#endif
