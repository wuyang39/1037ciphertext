#
# A1-22 SGX quote probe (Intel SGX SDK layout).
#
#   make SGX_DEBUG=0   # non-debug enclave launch, KAS accepts
#   make SGX_DEBUG=1   # debug enclave launch, KAS must reject
#

SGX_SDK ?= /opt/intel/sgxsdk
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

ifneq ($(filter $(SGX_ARCH),x64),x64)
  $(error SGX_ARCH must be x64)
endif

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
  SGX_COMMON_CFLAGS += -O0 -g
else
  SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

DCAP_QL_Library_Name := sgx_dcap_ql
QCNL_Library_Name := sgx_default_qcnl_wrapper
Urts_Library_Name := sgx_urts

App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

ifeq ($(SGX_DEBUG), 1)
  App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else
  App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L/usr/lib/x86_64-linux-gnu \
	-l$(DCAP_QL_Library_Name) -l$(QCNL_Library_Name) -l$(Urts_Library_Name) \
	-ldl -lpthread

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Name := quote_probe

######## Enclave Settings ########

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie \
	-ffunction-sections -fdata-sections -fstack-protector-strong
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib \
	-nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) \
	-l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
	-Wl,-z,relro,-z,now,-z,noexecstack \
	-Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Test_Key := Enclave/Enclave_private_sample.pem

ifeq ($(SGX_DEBUG), 1)
  Build_Mode = HW_DEBUG
else
  Build_Mode = HW_RELEASE
endif

.PHONY: all target clean

all: .config_$(Build_Mode)_$(SGX_ARCH)
	$(MAKE) target

target: $(App_Name) $(Signed_Enclave_Name)
	@echo "Built $(App_Name) in $(Build_Mode) mode."

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) \
		$(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

App/Enclave_u.c:
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Cpp_Objects): App/Enclave_u.c
App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/Enclave_t.c:
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Cpp_Objects): Enclave/Enclave_t.c
Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "No $(Enclave_Test_Key); generating a test signing key."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Enclave_Name) \
		-out $@ -config $(Enclave_Config_File)
	@rm -f $(Enclave_Name)
	@echo "SIGN =>  $@"

clean:
	@rm -f $(App_Name) App/*.o App/Enclave_u.* .config_*
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) \
		Enclave/Enclave_t.*
