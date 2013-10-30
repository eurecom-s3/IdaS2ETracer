/*
 * Copyright:   Eurecom, 2013
 * Author:      Luca Bruno <lucab@debian.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/


#include "IdaTracer.h"

#define __LINUX__ 1
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>


int IDAP_init(void)
{
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
	return;
}

// TODO: check input arg
void IDAP_run(int arg)
{
	char * TraceName = askfile_c(0, "ExecutionTrace.dat", "S2E ExecutionTrace.dat location: ");
	sval_t pathNr = 0;
	int ret = asklong(&pathNr, "Path Number");
	if (TraceName && ret) {
		msg("[I] Importing from trace file %s\n", TraceName);

		// Initialize the IDA trace buffer
		set_trace_size(0);
		const std::string TraceFiles(TraceName);
		s2etools::IdaTracerTool trace(TraceFiles);

		if (trace.existPath(pathNr)) {
			trace.flatTrace(pathNr);
			msg("[I] Imported path number %d\n", pathNr);
		} else {
			msg("[E] Path number %d doesn't exist in trace %s!\n", pathNr, TraceName);
		}

	} else {
		msg("[E] S2E trace import aborted!");
	}

    return;
}

char IDAP_comment[] 	= "S2E Trace importer";
char IDAP_help[] 		= "";
char IDAP_name[] 		= "Import S2E trace";
char IDAP_hotkey[] 		= "Ctrl-Alt-i";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  IDAP_init,
  IDAP_term,
  IDAP_run,
  IDAP_comment,
  IDAP_help,
  IDAP_name,
  IDAP_hotkey
};
