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
 * This script uses safe-stable-stringify which is currently vendored
 * in ./scripts/vendor/safe-stable-stringify. It was fetched via:
 *
 *     npm install safe-stable-stringify@2.5.0
 */
const dgram = require('node:dgram');
const stringify = require('./vendor/safe-stable-stringify').configure({
  deterministic: false,
});


// Environment variable based configuration.
const udp_port = parseInt(process.env.UDP_LOGGING_PORT || '9514');
const udp_host = process.env.UDP_LOGGING_HOST || '127.0.0.1';
const udp_type = process.env.UDP_LOGGING_TYPE || 'udp4';
const udp_format = process.env.UDP_LOGGING_FORMAT || 'tagged-rfc5424';
const udp_suppress_errors_interval_ms = parseInt(process.env.UDP_SUPPRESS_ERRORS_INTERVAL_MS || '1000');
const udp_skip_logging_framework = parseInt(process.env.UDP_SKIP_LOGGING_FRAMEWORK || '1');

if (udp_skip_logging_framework !== 1 && udp_skip_logging_framework !== 0 ) {
  console.error(`udp-logging: UDP_SKIP_LOGGING_FRAMEWORK must be 0 or 1, got '${udp_skip_logging_framework}'`)
  process.exit(1);
}

var total = 0;
var errors = 0;

// Whether to suppores
var suppress_errors = false;


// This approximates what LogAscii::use_json=T should be doing. Log
// all fields with a &log attribute and flatten the record keys.
const to_json = (rec) => {
  const log_rec = zeek.select_fields(rec, zeek.ATTR_LOG)
  const flat_rec = zeek.flatten(log_rec)
  return stringify(flat_rec);
}


// The JSONL format is a JSON rendering of a log record.
//
// It may not be 100% exact to what the logging framework produces, but
// that's probably some sort of bug or quirk somewhere.
//
// If you use this format, you likely want to also use a Log::default_ext_func
// that includes the path of the log.
const format_raw_json = (path, rec) => {
  return to_json(rec);
};


// zeek_filename tagged RFC-5424 for Cisco SNA.
//
const facility = 10; // Security/Authorization
const severity = 5; // Notice
const pri = `<${facility * 8 + severity}>`;
const version = '1';
const hostname = zeek.global_vars['Cluster::node'] ? `zeek-${zeek.global_vars['Cluster::node']}` : 'zeek';
const app_name = 'zeekjs-udp-logging';
const procid = `${process.pid}`;
const msgid = '-';

const sd_escape_value = (value) => {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\]/g, '\\]');
}

const format_tagged_rfc5424 = (path, rec) => {
  let ts = new Date().toISOString();
  let header = `${pri} ${version} ${ts} ${hostname} ${app_name} ${procid} ${msgid}`

  // Hard-coded structured data.
  let sd = `[zeek_filename="${sd_escape_value(path)}.log"]`

  let jsonl = to_json(rec);

  return `${header} ${sd} ${jsonl}`;
};

// Supported formatters.
const formatters = {
  'raw-json': format_raw_json,
  'tagged-rfc5424': format_tagged_rfc5424,
}

const formatter = formatters[udp_format];
if (!formatter) {
  console.error(`udp-logging: unknown format: ${udp_format}`);
  process.exit(1);
}

function make_client() {
  console.log(`udp-logging: creating client for ${udp_host}:${udp_port}`);
  let c = dgram.createSocket(udp_type);

  c.on('error', (err) => {
    ++errors;

    // Log an error once, then suppress it for udp_suppress_errors_interval_ms
    // milliseconds to avoid flooding the console/worker output.
    if (!suppress_errors) {
      console.error(`udp-logging: client error: ${err} (total=${total} errors=${errors})`);

      suppress_errors = true;
      setTimeout(() => { suppress_errors = false; }, udp_suppress_errors_interval_ms);
    }
  });

  c.connect(udp_port, udp_host);
  return c;
}

var client = make_client();

const path_cache = {}

// Returns the path of the default filter attached to stream_id.
const get_default_path = (stream_id) => {
  if (!path_cache[stream_id]) {
    let filter = zeek.invoke('Log::get_filter', [stream_id, 'default']);
    path_cache[stream_id] = filter.path;
  }

  return path_cache[stream_id];
}

// Hook for Log::log_stream_policy.
zeek.hook('Log::log_stream_policy', (rec, stream_id) => {
  ++total;

  let path = get_default_path(stream_id);
  let msg = formatter(path, rec);

  client.send(msg);

  // Returning true means Zeek will process this record,
  // returning false is like break, skipping the remaining
  // logging pipeline implemented in Zeek.
  return udp_skip_logging_framework == 0;
});

// Output a summary on shutdown.
zeek.on('zeek_done', { priority: -1000 }, () => {
  console.log(`udp-logging: done (total=${total} errors=${errors})`);
});
