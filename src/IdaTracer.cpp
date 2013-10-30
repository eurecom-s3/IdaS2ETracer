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

using namespace s2etools;
using namespace s2e::plugins;

namespace s2etools
{

IdaTrace::IdaTrace(LogEvents *events):
		m_events(events)
{
    m_connection = events->onEachItem.connect(
            sigc::mem_fun(*this, &IdaTrace::onItem)
            );
    m_traces = new tevinforeg_vec_t();
}

IdaTrace::~IdaTrace()
{
    m_connection.disconnect();
	free(m_traces);
}

void IdaTrace::onItem(unsigned traceIndex,
            const s2e::plugins::ExecutionTraceItemHeader &hdr,
            void *item)
{
    if (hdr.type == s2e::plugins::TRACE_INSTR_START) {
        const s2e::plugins::ExecutionTraceInstr *te =
                (const s2e::plugins::ExecutionTraceInstr*) item;

        switch (te->arch) {
        case s2e::plugins::ExecutionTraceInstr::ARM:
        {
        	tev_reg_values_t regsInfo;
            for (unsigned i = 0; i < ARM_NR_REG; ++i) {
            	tev_reg_value_t r(i, 0xDEADDEAD);
                if ((te->symbMask & 1<<i) == 0)
                	r.value._set_int(te->arm_registers[i]);
				regsInfo.push_back(r);
            }
        	regsInfo.push_back(tev_reg_value_t(ARM_NR_REG, te->pc));
            recordEvent(te->pc, regsInfo);
        	break;
        }
        case s2e::plugins::ExecutionTraceInstr::X86_64:
        {
        	tev_reg_values_t regsInfo;
        	for (unsigned i = 0; i < X86_NR_REG; ++i) {
            	tev_reg_value_t r(i, 0xDEADDEAD);
                if ((te->symbMask & 1<<i) == 0)
                	r.value._set_int(te->x64_registers[i]);
				regsInfo.push_back(r);
            }
            recordEvent(te->pc, regsInfo);
        	break;
        }
        case s2e::plugins::ExecutionTraceInstr::X86:
        {
        	tev_reg_values_t regsInfo;
        	for (unsigned i = 0; i < X86_NR_REG; ++i) {
            	tev_reg_value_t r(i, 0xDEADDEAD);
                if ((te->symbMask & 1<<i) == 0)
                	r.value._set_int(te->x86_registers[i]);
				regsInfo.push_back(r);
            }
            recordEvent(te->pc, regsInfo);
        	break;
        }
        default:
        	assert (false && "Architecture type unknown");
        	break;
        }

        return;
    }
}

void IdaTrace::recordEvent(const uint64_t& pc, tev_reg_values_t& regs) {
	tev_info_t tevInfo = {tev_insn, 0, pc};
	tev_info_reg_t singleEvent = {tevInfo, regs};
	m_traces->push_back(singleEvent);
}

IdaTracerTool::IdaTracerTool(const std::string& tracefile):
		m_parser(), m_pb(&m_parser)
{
    m_parser.parse(tracefile);

    PathSet paths;
    m_pb.getPaths(paths);

    if (m_pathlist.empty()) {
        PathSet::iterator pit;
        for (pit = paths.begin(); pit != paths.end(); ++pit) {
            m_pathlist.push_back(*pit);
        }
    }
}

IdaTracerTool::~IdaTracerTool()
{

}

bool IdaTracerTool::existPath(int& pathNr)
{
	return (std::find(m_pathlist.begin(), m_pathlist.end(), pathNr) != m_pathlist.end());

}

void IdaTracerTool::flatTrace(int& pathNr)
{
    IdaTrace trace(&m_pb);
    m_pb.processPath(pathNr);
    dbg_add_many_tevs(trace.m_traces);
}

}



