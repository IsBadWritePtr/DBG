CLFL_BUILD_release = /DRELEASE
CLFL_BUILD_debug   = /Z7 /DDEBUG 

LDFL_BUILD_release = /RELEASE
LDFL_BUILD_debug   = /DEBUG

all: core link r

core:
	@icl.exe /nologo /I$(PROJECT_INCLUDE_PATH)/ /FI$(PROJECT_INCLUDE_PATH)/stdafx.h /Wall /fast /Qsafeseh- /Qipo /Qunroll-aggressive /Ob2 /Ox /GA /GF /GS:off /Zp16 /Qsfalign16 /Qfnalign:8 /Qalign-loops:16 /Qcf-protection:none /Qms0 /DYNAMICBASE /Qfreestanding $(CLFL_BUILD_$(PROJECT_BUILD)) /c source/source/*.c /Fo:$(PROJECT_OBJECT_PATH)/

link:
	@xilink.exe /NOLOGO /TIME /MACHINE:$(PROJECT_ARCH) /DYNAMICBASE /NODEFAULTLIB /SAFESEH:NO /SUBSYSTEM:CONSOLE /OPT:REF /GUARD:NO /ENTRY:Entry KERNEL32.LIB USER32.LIB $(LDFL_BUILD_$(PROJECT_BUILD)) /MAP:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgMaster.map /PDB:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgMaster.pdb /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgMaster.exe \
	$(PROJECT_OBJECT_PATH)/*.obj \

r:
	"$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/DlgMaster.exe" /n \\.\pipe\{6F9A9D97-3E66-767D-4C3C-C09739483C20} /f lastrun.txt

drmem:
	drmemory -- "%PROJECT_BIN_PATH%/%PROJECT_BUILD%/DlgMaster.exe" /n \\.\pipe\{6F9A9D97-3E66-767D-4C3C-C09739483C20}
