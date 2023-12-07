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

#ifndef LIBNFC_TF_HAL_H
#define LIBNFC_TF_HAL_H

#include <sys/types.h>

extern void libnfc_tf_hal_initialize( void );
extern int libnfc_tf_hal_open( char* dev_file );
extern void libnfc_tf_hal_close( void );
extern void libnfc_tf_hal_flush( void );
extern int libnfc_tf_hal_write( uint8_t *pbuf, size_t len );
extern int libnfc_tf_hal_read_timeout( uint8_t *pbuf, size_t len, struct timeval *tval );
extern int libnfc_tf_hal_read( uint8_t *pbuf, size_t len );
extern void libnfc_tf_hal_get_random( uint8_t *pbuf, size_t len );

#endif

