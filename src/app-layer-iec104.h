/* Copyright (C) 2015-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 */

#ifndef __APP_LAYER_IEC104_H__
#define __APP_LAYER_IEC104_H__

#include "detect-engine-state.h"

#include "queue.h"

#include "rust.h"

void RegisterIec104Parsers(void);
void Iec104ParserRegisterTests(void);

typedef struct Iec104Transaction
{
    /** Internal transaction ID. */
    uint64_t tx_id;

    /** Application layer events that occurred
     *  while parsing this transaction. */
    AppLayerDecoderEvents *decoder_events;

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    AppLayerTxData tx_data;

    TAILQ_ENTRY(Iec104Transaction) next;

} Iec104Transaction;

typedef struct Iec104State {

    /** List of Iec104 transactions associated with this
     *  state. */
    TAILQ_HEAD(, Iec104Transaction) tx_list;

    /** A count of the number of transactions created. The
     *  transaction ID for each transaction is allocated
     *  by incrementing this value. */
    uint64_t transaction_max;
} Iec104State;

#endif /* __APP_LAYER_IEC104_H__ */
