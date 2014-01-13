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


#include <iostream>
#include <fstream>
#include <cstdlib>

#include "TraceEntries.h"

#define __LINUX__ 1
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <dbg.hpp>


int IDAP_init(void)
{
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
	return;
}

unsigned int traceImport(char *traceName, unsigned pathNr) {

    std::ifstream trace(traceName);
    if (!trace.good()) {
        msg("[E] Unable to read file %s", traceName);
        return 0;
    }

    bool fileOver=false;
    unsigned itemNr = 0, pathItem = 0;

    // We handle item sequentially, pre-allocate on stack here
    s2e::plugins::ExecutionTraceItemHeader hdr;
    s2e::plugins::ExecutionTraceInstr instrItem;
    tevinforeg_vec_t m_traces;
    ea_t previousPc=-1;

    while(!fileOver && !trace.eof() ) {
        trace.read((char*) &hdr, sizeof(hdr));
        if (trace.gcount() != sizeof(hdr)) {
            if (!trace.eof())
                msg("[E] Short read of %d (expected %d) at item %d\n", trace.gcount(), sizeof(hdr), itemNr);
            fileOver = true;
            continue;
        }
        if (hdr.type >= s2e::plugins::TRACE_MAX) {
            msg("[E] Corrupted trace file at item %d\n", itemNr);
            return EXIT_FAILURE;
        }

        // We only care about InstructionTracer entries
        if (hdr.type == s2e::plugins::TRACE_INSTR_START && hdr.stateId == pathNr) {
            trace.read((char*) &instrItem, sizeof(instrItem));
            tev_reg_values_t regsInfo;
            for (unsigned i = 0; i < ARM_NR_REG; ++i) {
                if ((instrItem.symbMask & 1<<i) == 0) {
                	regsInfo.push_back(tev_reg_value_t(i, instrItem.arm_registers[i]));
                } else {
                    regsInfo.push_back(tev_reg_value_t(i, 0x00DEAD00));
                }
            }
            regsInfo.push_back(tev_reg_value_t(15, instrItem.pc));
            regsInfo.push_back(tev_reg_value_t(16, instrItem.flags));
            if (itemNr == 0) {
                // First entry is empty to setup the replayer
                tev_info_t regSetup = {tev_insn, 1, (ea_t) -1};
                tev_info_reg_t regEvent = {regSetup, regsInfo};
                m_traces.push_back(regEvent);
            } else {
                tev_info_t tevInfo = {tev_insn, 1, previousPc };
                tev_info_reg_t singleEvent = {tevInfo, regsInfo};
                m_traces.push_back(singleEvent);
                pathItem++;
            }
            previousPc = (ea_t) instrItem.pc;
        } else {
            trace.seekg(hdr.size, std::ios_base::cur);
        }
        itemNr++;
    }

    if (!dbg_add_many_tevs(&m_traces))
        pathItem=0;

    trace.close();
    return pathItem;

}

// TODO: check input arg
void IDAP_run(int arg)
{
    if(!load_debugger("replay", false)) {
        msg("[E] Unable to use trace replayer, please check your environment!\n");
        return;
    }
	char * TraceName = askfile_c(0, "ExecutionTrace.dat", "S2E ExecutionTrace.dat location: ");
	sval_t pathNr = 0;
	int ret = asklong(&pathNr, "Path Number");
	if (TraceName && ret) {
		msg("[I] Importing from trace file %s\n", TraceName);
        clear_trace();
        set_trace_size(0);
		dbg_add_thread(1);
        unsigned int imported = traceImport(TraceName, (unsigned int) pathNr);
		if (imported != 0) {
			msg("[I] Imported %d entries for path number %d\n", imported, pathNr);
            graph_trace();
		} else {
			msg("[E] Unable to import path number %d from trace %s!\n", pathNr, TraceName);
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
