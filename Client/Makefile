CLFL_BUILD_release = /DRELEASE
CLFL_BUILD_debug   = /Z7 /DDEBUG /Qfreestanding

LDFL_BUILD_release = /RELEASE /NODEFAULTLIB /NOENTRY /DLL /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgClient3.0.dll
LDFL_BUILD_debug   = /DEBUG /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.exe

all: core link

core:
	@icl.exe /nologo /I$(PROJECT_INCLUDE_PATH)/ /Wall /fast /Qsafeseh- /Qipo- /Qip /Qunroll-aggressive /Ob2 /Os /GA /GF /GS:off /Qcf-protection:none /Qms0 /DYNAMICBASE $(CLFL_BUILD_$(PROJECT_BUILD)) /c source/source/*.c /Fo:$(PROJECT_OBJECT_PATH)/

link:
	@xilink.exe /NOLOGO /TIME /MACHINE:$(PROJECT_ARCH) /DYNAMICBASE /SAFESEH:NO /SUBSYSTEM:CONSOLE /OPT:REF /GUARD:NO $(LDFL_BUILD_$(PROJECT_BUILD)) /MAP:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.map /PDB:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.pdb \
	$(PROJECT_OBJECT_PATH)/*.obj \

lib:
	@xilib /qnoipo /NOLOGO /NODEFAULTLIB $(PROJECT_OBJECT_PATH)/*.obj /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgClient3.0.lib

r:
	"$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.exe"

drmem:
	drmemory -- "$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.exe"
	
windbg:
	"$(WINDBG)$(PROJECT_ARCH)/windbg.exe" "$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/Client.exe"
	