/*
 * Copyright (c) 2025 by the Zeek Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * A proof-of-concept JavaScript based UDP logger to integrate
 * Zeek with Cisco's Secure Network Analytics platform.
 *
 * See: https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/zeek/7_5_2_Zeek_Configuration_Guide_DV_1_0.pdf
 *
 * If this doesn't fulfill your performance or reliability requirements, you
 * can always implement a C++ Zeek plugin adding a UDP writer. See the Zeek
 * documentation for more details.
 *
 * This script uses safe-stable-stringify for rendering log records to JSON.
 *
 *     npm install safe-stable-stringify@2.5.0
 */
const dgram = require('node:dgram');
const stringify = require('safe-stable-stringify').configure({
  deterministic: false,
});

const udp_port = parseInt(process.env.UDP_PORT || '9514');
const udp_host = process.env.UDP_HOST || '127.0.0.1';
const udp_type = process.env.UDP_TYPE || 'udp4';
const udp_delay_ms = process.env.UDP_DELAY_MS || '25';  // discard writes for that many milliseconds on error

var ready = false;
var stop = false;

function make_client() {
  console.log(`udp-logging: creating client for ${udp_host}:${udp_port}`);
  let c = dgram.createSocket(udp_type);

  c.on('error', (err) => {
    console.error(`udp-logging: client error: ${err}`);

    // Any error results in ready set to false, so we skip sending
    // logs at that point until we try again
    ready = false;

    // Attempt to resend after 25ms
    setTimeout(() => {
      if (stop)
        return;

      client = make_client();
    }, udp_delay_ms);
  });

  c.on('connect', (err) => {
    ready = true;
  });

  c.connect(udp_port, udp_host);
  return c;
}

var client = make_client();

// This approximates what LogAscii::use_json=T, selecting only &log
// fields and flattening the resulting structure.
const to_json = (rec) => {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG)
  const flat_rec = zeek.flatten(log_rec)
  return stringify(flat_rec);
}

const path_cache = {}

const get_default_path = (stream_id) => {
  if ( path_cache[stream_id] === undefined ) {
    let filter = zeek.invoke('Log::get_filter', [stream_id, 'default']);
    path_cache[stream_id] = `${filter.path}.log`;
  }

  return path_cache[stream_id];
}

// Count discarded writes and output a summary at zeek_done() time.
var total_discarded = 0;
var path_discarded = {}

zeek.on('zeek_done', {priority: -1000}, () => {
  stop = true
  if ( total_discarded > 0 )
    console.error(`udp-logging: Discarded a total of ${total_discarded} writes`);

  for ( const path in path_discarded )
    console.error(`udp-logging:   ${path}: ${path_discarded[path]}`);
});

zeek.hook('Log::log_stream_policy', (rec, stream_id) => {
  let data = to_json(rec);
  let path = get_default_path(stream_id);

  if (!ready) {
    ++total_discarded;
    path_discarded[path] = (path_discarded[path] || 0) + 1;
    return;
  }

  client.send(`zeek_filename="${path}"${data}\n`);

  // Skip the rest of Zeek's logging pipeline. Remove this
  // return statement if you want Zeek to continue logging
  // to files.
  return false;
});
