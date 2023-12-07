/*
 *
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
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <errno.h>

#include "libnfc_tf.h"
#include "libnfc_tf_local.h"

typedef struct {
	int fd;
	char open_fname[32];
	struct termios config;
	struct termios config_backup;
} libnfc_tf_hal_context_t;

#define PORT_DEVICE_NAME "/dev/ttyACM0"
#define PORT_CONFIG_RATE B115200


static libnfc_tf_hal_context_t gNfcHalContext;


void libnfc_tf_hal_initialize( void )
{
	memset(&gNfcHalContext, 0, sizeof(libnfc_tf_hal_context_t));
	gNfcHalContext.fd = -1;
}


int libnfc_tf_hal_open( char* dev_file )
{
	int dev_fd = -1;
	char *fname;

	fname = ( dev_file ) ? dev_file: PORT_DEVICE_NAME;
	dev_fd = open( fname, O_RDWR|O_NOCTTY|O_NONBLOCK );
	if ( dev_fd < 0 ){
		return -1;
	}

	strcpy( gNfcHalContext.open_fname, fname ); 
	tcgetattr( dev_fd, &gNfcHalContext.config_backup );

	memset( &gNfcHalContext.config, 0, sizeof(struct termios) );
	gNfcHalContext.config.c_cflag = CS8 | CLOCAL | CREAD;
	gNfcHalContext.config.c_iflag = IGNPAR;
	gNfcHalContext.config.c_oflag = 0;
	gNfcHalContext.config.c_lflag = 0;
	gNfcHalContext.config.c_cc[VTIME] = 5;
	gNfcHalContext.config.c_cc[VMIN] = 1;
	cfsetospeed( &gNfcHalContext.config, PORT_CONFIG_RATE );

	tcsetattr( dev_fd, TCSANOW, &gNfcHalContext.config );

	gNfcHalContext.fd = dev_fd;

	return 0;
}

void libnfc_tf_hal_close( void )
{
	if ( gNfcHalContext.fd != -1 ){
		tcsetattr( gNfcHalContext.fd, TCSANOW, &gNfcHalContext.config_backup );
		close( gNfcHalContext.fd );

		gNfcHalContext.fd = -1;
	}
}

void libnfc_tf_hal_flush( void )
{
	tcflush( gNfcHalContext.fd, TCIFLUSH );
}

int libnfc_tf_hal_write( uint8_t *pbuf, size_t len )
{
	int ret;

	if ( pbuf == NULL ){
		return -1;
	}

	ret = write( gNfcHalContext.fd, pbuf, len );
	libnfc_tf_hal_flush();

	return ret;
}

// RICOH ADD-S Felica Security Access
int libnfc_tf_hal_read_loop(int fd, uint8_t *pbuf, int len) {
	int ret;
	int tmp;
	int read_len = 0;
	int count = 0;
	do {
		ret = read(fd, pbuf + read_len, len - read_len);
		if (ret > 0) {
			read_len += ret;
			count = 0;
		} else {
			tmp = errno;
			if (tmp != EAGAIN && tmp != EWOULDBLOCK) {
				read_len = ret;
				break;
			}
			count++;
			if (count > NFC_TF_READ_TRY_TIME_OUT) {
				read_len = ret;
				break;
			}
			usleep(NFC_TF_READ_TRY_WAIT);
		}
	} while(read_len < len);
	return read_len;
}

int libnfc_tf_hal_read_packet(int fd, uint8_t *pbuf, size_t len) {
	int ret;
	int read_len = 0;
	int recv_len = 0;
	int param_len = len - (NFC_TF_CMD_HEADER_BYTE + NFC_TF_CMD_RESULT_BYTE
			+ NFC_TF_CMD_PARAM_LEN_BYTE + NFC_TF_CMD_BCC_BYTE);
	if (param_len < 0) {
		ALOGE("libnfc_tf_hal_read_loop buffer length NG[%d]", len);
		return -1;
	}
	do {
		ret = libnfc_tf_hal_read_loop(fd, pbuf, NFC_TF_CMD_HEADER_BYTE);
		if (ret <= 0) {
			ALOGE("libnfc_tf_hal_read_loop header read NG[%d]", errno);
			return ret;
		} else if (pbuf[0] == NFC_TF_CMD_HEADER_NACK) {
			ALOGE("libnfc_tf_hal_read_loop header is Nack");
			return NFC_TF_ERR;
		}
	} while(pbuf[0] != NFC_TF_CMD_HEADER_RESULT);
	read_len += NFC_TF_CMD_HEADER_BYTE;
	
	ret = libnfc_tf_hal_read_loop(fd, pbuf + read_len, NFC_TF_CMD_RESULT_BYTE);
	if (ret <= 0) {
		ALOGE("libnfc_tf_hal_read_loop result read NG[%d]", errno);
		return ret;
	}
	read_len += NFC_TF_CMD_RESULT_BYTE;
	
	ret = libnfc_tf_hal_read_loop(fd, pbuf + read_len, NFC_TF_CMD_PARAM_LEN_BYTE);
	if (ret <= 0) {
		ALOGE("libnfc_tf_hal_read_loop length read NG[%d]", errno);
		return ret;
	}
	recv_len = (pbuf + read_len)[0] + ((pbuf + read_len)[1] * 0x0100);
	if (recv_len > NFC_TF_CMD_PARAM_MAX_LEN) {
		ALOGE("libnfc_tf_hal_read_loop receive length[%d] is over max", recv_len);
		return -1;
	} else if (recv_len > param_len) {
		ALOGE("libnfc_tf_hal_read_loop buffer length[%d] is over receive length[%d]", param_len, recv_len);
		return -1;
	}
	recv_len += NFC_TF_CMD_BCC_BYTE;
	read_len += NFC_TF_CMD_PARAM_LEN_BYTE;
	
	ret = libnfc_tf_hal_read_loop(fd, pbuf + read_len, recv_len);
	if (ret <= 0) {
		ALOGE("libnfc_tf_hal_read_loop param read NG[%d]", errno);
	} else {
		ret += read_len;
	}
	return ret;
}
// RICOH ADD-E Felica Security Access

int libnfc_tf_hal_read_timeout( uint8_t *pbuf, size_t len, struct timeval *tval )
{
	fd_set read_fds;
	int ret;

	if ( pbuf == NULL ){
		return -1;
	}

	FD_ZERO( &read_fds );
	FD_SET( gNfcHalContext.fd, &read_fds );
	
	ret = select( gNfcHalContext.fd + 1, &read_fds, NULL, NULL, tval );
	if ( ret <= 0 ){
             return ret;
	}

	// RICOH MOD-S Felica Security Access
	//ret = read( gNfcHalContext.fd, pbuf, len );
	ret = libnfc_tf_hal_read_packet( gNfcHalContext.fd, pbuf, len );
	// RICOH MOD-E Felica Security Access
	return ret;
}


int libnfc_tf_hal_read( uint8_t *pbuf, size_t len )
{
	int ret;

	// RICOH MOD-S Felica Security Access
	//ret = read( gNfcHalContext.fd, pbuf, len );
	ret = libnfc_tf_hal_read_packet( gNfcHalContext.fd, pbuf, len );
	// RICOH MOD-E Felica Security Access
	return ret;
}

void libnfc_tf_hal_get_random( uint8_t *pbuf, size_t len )
{
	int fd;
	fd = open( "/dev/urandom", O_RDONLY );
	if ( fd >= 0 ){
		read( fd, pbuf, len );
		close( fd );
	}
}

