/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <fstream>
#include <iostream>

#include "backends/p4test/version.h"
#include "control-plane/p4RuntimeSerializer.h"
#include "ir/ir.h"
#include "ir/json_loader.h"
#include "lib/log.h"
#include "lib/error.h"
#include "lib/exceptions.h"
#include "lib/gc.h"
#include "lib/crash.h"
#include "lib/nullstream.h"
#include "frontends/common/applyOptionsPragmas.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/frontend.h"
#include "frontends/p4/toP4/toP4.h"
#include "midend.h"

class P4TestOptions : public CompilerOptions {
 public:
    bool parseOnly = false;
    bool validateOnly = false;
    bool loadIRFromJson = false;
    P4TestOptions() {
        registerOption("--parse-only", nullptr,
                       [this](const char*) {
                           parseOnly = true;
                           return true; },
                       "only parse the P4 input, without any further processing");
        registerOption("--validate", nullptr,
                       [this](const char*) {
                           validateOnly = true;
                           return true;
                       },
                       "Validate the P4 input, running just the front-end");
        registerOption("--fromJSON", "file",
                       [this](const char* arg) {
                           loadIRFromJson = true;
                           file = arg;
                           return true;
                       },
                       "read previously dumped json instead of P4 source code");
     }
};

using P4TestContext = P4CContextWithOptions<P4TestOptions>;

static void log_dump(const IR::Node *node, const char *head) {
    if (node && LOGGING(1)) {
        if (head)
            std::cout << '+' << std::setw(strlen(head)+6) << std::setfill('-') << "+\n| "
                      << head << " |\n" << '+' << std::setw(strlen(head)+3) << "+" <<
                      std::endl << std::setfill(' ');
        if (LOGGING(2))
            dump(node);
        else
            std::cout << *node << std::endl; }
}
#define BALA
#ifdef BALA
/* if p4test passed with --validate,  Following GC error comes
free(): invalid pointer 
*/
extern "C" {

    //#define UNIX_PATH_MAX    108
    #define UNIX_PATH_MAX    120
    #define MAX_CMDLINE_ARGS    10

int p4frontendlib_entry(char filename[]) {    // file reading and update argc/argv
    FILE* fp = fopen(filename, "r");

    #if 1

    std::cout << "Begin the compiler arguments processing ...." << "\n \n";
    std::cout << "filename: " << filename << "\n";

    #endif

    if (fp == NULL)
        exit(EXIT_FAILURE);     // error code. uncaught exception

    char* line = NULL;
    char **argv = NULL;
    size_t len = 0;
    size_t argc = 0;

    // get number of params (including compile_cmd)

    if (getline(&line, &len, fp) == -1)
        exit(EXIT_FAILURE);     // error code. uncaught exception
    else
        argc = atoi(line);      // error check 0 || > 10. compiler args sanitization
    if ((argc == 0) || (argc > (MAX_CMDLINE_ARGS)))
            exit(EXIT_FAILURE);     // error code. uncaught exception

    #if 1
    std::cout << "num cmd args: " << argc << "\n";
    #endif

    // check alloc failure
    argv = (char **) new char[(sizeof(char *[(argc + 1)]))];
    if (argv == NULL)
        exit(EXIT_FAILURE);     // error code. uncaught exception

    // Allocate pointers as per argc. last element NULL. Deallocate at the exit
    for (size_t args = 0; args < argc; args ++) {
        argv[args] = (char *) new char[UNIX_PATH_MAX];
        if (argv[args] == NULL)
            exit(EXIT_FAILURE);     // error code. uncaught exception
	len = 0;
        if ((getline(&(argv[args]), &len, fp)) == -1) {
            exit(EXIT_FAILURE);     // error code. uncaught exception
        }

	#if 1
        std::cout << (argv[args]) << " len " << len << "\n";
	#endif 

        for (int j = 0; j < UNIX_PATH_MAX; j++) {
            if ((argv[args][j]) == '\0') {
            // do null termination
                argv[args][j-1] = '\0';
                len = (j - 1);     // actual length, lf
                break;
            }
        }
        #if 1
        std::cout << (argv[args]) << " len " << len << "\n";
        #endif
    }
    argv[argc] = NULL;      // last element

    fclose(fp);     // close file.

    //if (line)       // no need to free argv for now
    //    free(line);

    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif

#else 
int main(int argc, char *const argv[]) {
#endif /* BALA */
		
    setup_gc_logging();
    setup_signals();

    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif

    AutoCompileContext autoP4TestContext(new P4TestContext);
    auto& options = P4TestContext::get().options();
    options.langVersion = CompilerOptions::FrontendVersion::P4_16;
    options.compilerVersion = P4TEST_VERSION_STRING;

    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif
    if (options.process(argc, argv) != nullptr) {
            if (options.loadIRFromJson == false)
                    options.setInputFile();
    }
    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif
    if (::errorCount() > 0)
        return 1;
    const IR::P4Program *program = nullptr;
    auto hook = options.getDebugHook();
    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif
    if (options.loadIRFromJson) {
        std::ifstream json(options.file);
        if (json) {
            JSONLoader loader(json);
            const IR::Node* node = nullptr;
            loader >> node;
            if (!(program = node->to<IR::P4Program>()))
                error("%s is not a P4Program in json format", options.file);
        } else {
            error("Can't open %s", options.file); }
    } else {
        program = P4::parseP4File(options);

        if (program != nullptr && ::errorCount() == 0) {
            P4::P4COptionPragmaParser optionsPragmaParser;
            program->apply(P4::ApplyOptionsPragmas(optionsPragmaParser));

            if (!options.parseOnly) {
                try {
                    P4::FrontEnd fe;
                    fe.addDebugHook(hook);
                    program = fe.run(options, program);
                } catch (const std::exception &bug) {
                    std::cerr << bug.what() << std::endl;
                    return 1;
                }
            }
        }
    }

    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif
    log_dump(program, "Initial program");
    if (program != nullptr && ::errorCount() == 0) {
        P4::serializeP4RuntimeIfRequired(program, options);

        if (!options.parseOnly && !options.validateOnly) {
            P4Test::MidEnd midEnd(options);
            midEnd.addDebugHook(hook);
#if 0
            /* doing this breaks the output until we get dump/undump of srcInfo */
            if (options.debugJson) {
                std::stringstream tmp;
                JSONGenerator gen(tmp);
                gen << program;
                JSONLoader loader(tmp);
                loader >> program;
            }
#endif
            const IR::ToplevelBlock *top = nullptr;
            try {
                top = midEnd.process(program);
            } catch (const std::exception &bug) {
                std::cerr << bug.what() << std::endl;
                return 1;
            }
            log_dump(program, "After midend");
            log_dump(top, "Top level block");
        }
        if (options.dumpJsonFile)
            JSONGenerator(*openFile(options.dumpJsonFile, true), true) << program << std::endl;
        if (options.debugJson) {
            std::stringstream ss1, ss2;
            JSONGenerator gen1(ss1), gen2(ss2);
            gen1 << program;

            const IR::Node* node = nullptr;
            JSONLoader loader(ss1);
            loader >> node;

            gen2 << node;
            if (ss1.str() != ss2.str()) {
                error("json mismatch");
                std::ofstream t1("t1.json"), t2("t2.json");
                t1 << ss1.str() << std::flush;
                t2 << ss2.str() << std::flush;
                auto rv = system("json_diff t1.json t2.json");
                if (rv != 0) ::warning("json_diff failed with code %1%", rv);
            }
        }
    }

    #if 1
    std::cout << "Ending the compiler arguments processing ...." << "\n \n";
    #endif
    if (Log::verbose())
        std::cerr << "Done." << std::endl;
    return ::errorCount() > 0;
}
#ifdef BALA
}       // extern "C"
#endif
