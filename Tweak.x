#import <Foundation/Foundation.h>
#import <capstone/capstone.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <dlfcn.h>

struct sCSTypeRef {
    void *csCppData;
    void *csCppObj;
};

typedef struct sCSTypeRef CSTypeRef;
typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSymbolRef;

struct sCSRange {
    unsigned long long location;
    unsigned long long length;
};
typedef struct sCSRange CSRange;

static struct {
    CSSymbolicatorRef (*CreateWithTask)(task_t);
    CSSymbolOwnerRef (*GetSymbolOwnerWithAddressAtTime)(CSSymbolicatorRef, vm_address_t, uint64_t);
    CSSymbolRef (*GetSymbolWithAddress)(CSSymbolOwnerRef, vm_address_t);
    Boolean (*IsNull)(CSTypeRef);
    const char *(*GetSymbolName)(CSSymbolRef);
    const char *(*GetSymbolOwnerPath)(CSSymbolRef);
    CSRange (*GetSymbolRange)(CSSymbolRef);
} CS;

static struct {
    CSSymbolicatorRef symbolicator;
    csh cs_handle;
    task_t task;
} g_crash_details_state = {0};

@interface OSACrashReport : NSObject
- (BOOL)buildSharedDetailsState;
- (CSSymbolicatorRef)_getSymbolicator:(BOOL)a3;
- (id)_readDataAtAddress:(uint64_t)a3 size:(uint64_t)a4;
@end


static void _g_task_start_peeking(task_t task) {
    static dispatch_once_t onceToken;
    static void *_task_start_peeking_ptr = NULL;
    
    dispatch_once(&onceToken, ^{
        void *symbolication = dlopen("/System/Library/PrivateFrameworks/Symbolication.framework/Symbolication", RTLD_LAZY);
        _task_start_peeking_ptr = dlsym(symbolication, "task_start_peeking");
    });
    
    if (_task_start_peeking_ptr) {
        ((void (*)(task_t))_task_start_peeking_ptr)(task);
    }
}

static void _g_task_stop_peeking(task_t task) {
    static dispatch_once_t onceToken;
    static void *_task_stop_peeking_ptr = NULL;
    
    dispatch_once(&onceToken, ^{
        void *symbolication = dlopen("/System/Library/PrivateFrameworks/Symbolication.framework/Symbolication", RTLD_LAZY);
        _task_stop_peeking_ptr = dlsym(symbolication, "task_stop_peeking");
    });
    
    if (_task_stop_peeking_ptr) {
        ((void (*)(task_t))_task_stop_peeking_ptr)(task);
    }
}

static kern_return_t init_core_symbolication(void) {
    #define ASSERT_NOT_NULL(expr) if ((expr) == NULL) { printf("Failed to locate %s\n", #expr); return KERN_FAILURE; }
    void *core_symbolication_handle = dlopen("/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication", RTLD_LAZY);
    ASSERT_NOT_NULL(core_symbolication_handle);

    CS.CreateWithTask = dlsym(core_symbolication_handle, "CSSymbolicatorCreateWithTask");
    CS.GetSymbolOwnerWithAddressAtTime = dlsym(core_symbolication_handle, "CSSymbolicatorGetSymbolOwnerWithAddressAtTime");
    CS.GetSymbolWithAddress = dlsym(core_symbolication_handle, "CSSymbolOwnerGetSymbolWithAddress");
    CS.IsNull = dlsym(core_symbolication_handle, "CSIsNull");
    CS.GetSymbolName = dlsym(core_symbolication_handle, "CSSymbolGetName");
    CS.GetSymbolOwnerPath = dlsym(core_symbolication_handle, "CSSymbolOwnerGetPath");
    CS.GetSymbolRange = dlsym(core_symbolication_handle, "CSSymbolGetRange");
    
    ASSERT_NOT_NULL(CS.CreateWithTask);
    ASSERT_NOT_NULL(CS.GetSymbolOwnerWithAddressAtTime);
    ASSERT_NOT_NULL(CS.GetSymbolWithAddress);
    ASSERT_NOT_NULL(CS.IsNull);
    ASSERT_NOT_NULL(CS.GetSymbolName);
    ASSERT_NOT_NULL(CS.GetSymbolOwnerPath);
    ASSERT_NOT_NULL(CS.GetSymbolRange);
    return KERN_SUCCESS;
}

static const char *symbolicated_name_for_address(uint64_t address) {
    CSSymbolOwnerRef symbol_owner = CS.GetSymbolOwnerWithAddressAtTime(g_crash_details_state.symbolicator, address, 0x80000000u);
    if (CS.IsNull(symbol_owner)) {
        return NULL;
    }
    
    CSSymbolRef symbol = CS.GetSymbolWithAddress(symbol_owner, address);
    if (CS.IsNull(symbol)) {
        return NULL;
    }
    
    return CS.GetSymbolName(symbol);
}

NSDictionary *disassembledInstructionsStartingAtAddress(uint64_t address, NSData *data, int count) {
    
    NSMutableDictionary *disasCrashSection = [NSMutableDictionary new];
    disasCrashSection[@"crash_address"] = @(address);

    CSSymbolOwnerRef symbol_owner = CS.GetSymbolOwnerWithAddressAtTime(g_crash_details_state.symbolicator, address, 0x80000000u);
    if (!CS.IsNull(symbol_owner)) {
        const char *image_path = CS.GetSymbolOwnerPath(symbol_owner);
        disasCrashSection[@"crash_image"] = @(image_path ?: "???");

        const char *function_name = symbolicated_name_for_address(address);
        disasCrashSection[@"crash_function"] = @(function_name ?: "???");
    }
    
    cs_insn *insn;
    size_t instr_count = cs_disasm(g_crash_details_state.cs_handle, data.bytes, data.length, address, 0, &insn);
    if (instr_count > 0) {
        NSMutableDictionary *instructions = [NSMutableDictionary new];
        for (size_t i = 0; i < instr_count; i++) {
            NSString *instructionString = [NSString stringWithFormat:@"%s %s", insn[i].mnemonic, insn[i].op_str];
            if (insn[i].detail->arm64.op_count > 0 && insn[i].detail->arm64.operands[0].type == ARM64_OP_IMM) {
                if (insn[i].mnemonic[0] == 'b') {
                    const char *symbol_name = symbolicated_name_for_address(insn[i].detail->arm64.operands[0].imm);
                    if (symbol_name) {
                        instructionString = [instructionString stringByAppendingFormat:@" ; %s", symbol_name];
                    }
                }
                else {
                    uint8_t buffer[16] = {0};
                    vm_size_t size_read = 0;
                    if (vm_read_overwrite(g_crash_details_state.task, (mach_vm_address_t)address, sizeof(buffer), (vm_address_t)buffer, &size_read) == KERN_SUCCESS) {

                        NSMutableString *memoryString = [NSMutableString new];
                        for (int i = 0; i < size_read && i < 16; i++) {
                            [memoryString appendFormat:@"%02x%s", buffer[i], i < size_read - 1 ? " " : ""];
                        }

                        for (int i = 0; i < size_read && i < 16; i++) {
                            char c = buffer[i];
                            [memoryString appendFormat:@"%c", (c >= 32 && c <= 126) ? c : '.'];
                        }
                        
                        instructionString = [instructionString stringByAppendingFormat:@"    [ %@ ]", memoryString];
                    }
                }
            }

            NSString *addressString = [NSString stringWithFormat:@"%llx", insn[i].address]; 
            [instructions setObject:instructionString forKey:addressString];
        }
        cs_free(insn, instr_count);

        disasCrashSection[@"instructions"] = instructions;
    }
    return disasCrashSection;
}


%hook OSACrashReport

- (void)dumpProgramCounterBytes {
    if (![self buildSharedDetailsState]) {
        NSLog(@"Failed to build shared details state");
    }
    %orig();
}

%new
- (BOOL)buildSharedDetailsState {
    g_crash_details_state.task = (task_t)[[(id)self valueForKey:@"_task"] unsignedIntValue];
    if (g_crash_details_state.task == 0) {
        NSLog(@"Failed to get task");
        return NO;
    }

    mach_port_type_t portType;
    kern_return_t kr = mach_port_type(mach_task_self_, g_crash_details_state.task, &portType);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to get port type for task");
        return NO;
    }

    _g_task_start_peeking(g_crash_details_state.task);
    
    g_crash_details_state.symbolicator = [(OSACrashReport *)self _getSymbolicator:0];
    if (CS.IsNull(g_crash_details_state.symbolicator)) {
        NSLog(@"Failed to create symbolicator for task");
        return NO;
    }

    return YES;
}

- (void)generateLogAtLevel:(BOOL)a3 withBlock:(void (^)(NSDictionary *crashReportField))origAddCrashReportField {
    %orig(a3, origAddCrashReportField);
    
    NSDictionary *threadStateDecoded = (NSDictionary *)[(id)self valueForKey:@"_threadStateDecoded"];
    uint64_t pc = 0;
    if (threadStateDecoded) {
        NSDictionary *pc_obj = [threadStateDecoded objectForKey:@"pc"];
        if (pc_obj) {
            pc = [pc_obj[@"value"] unsignedLongLongValue];
        }
    }

    if (pc == 0) {
        NSLog(@"Failed to get pc");
        return;
    }

    NSData *pcData = [(OSACrashReport *)self _readDataAtAddress:pc size:128];  
    NSDictionary *disasCrashSectionContents = disassembledInstructionsStartingAtAddress(pc, pcData, 10);

    _g_task_stop_peeking(g_crash_details_state.task);

    if (disasCrashSectionContents) {
        NSDictionary *crashReportField = @{@"crash_disassembly": disasCrashSectionContents};
        origAddCrashReportField(crashReportField);
    }
}

%end


%ctor {
    if (init_core_symbolication() != KERN_SUCCESS) {
        NSLog(@"Failed to locate CoreSymbolication functions");
        return;
    }
    
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &g_crash_details_state.cs_handle) != CS_ERR_OK) {
        NSLog(@"Failed to initialize Capstone");
        return;
    }
    cs_option(g_crash_details_state.cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}
