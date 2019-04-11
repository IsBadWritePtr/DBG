CLFL_BUILD_release = /DRELEASE
CLFL_BUILD_debug   = /Z7 /DDEBUG 

LDFL_BUILD_release = /RELEASE libraries/$(PROJECT_ARCH)/DlgClient3.0.lib
LDFL_BUILD_debug   = /DEBUG libraries/$(PROJECT_ARCH)/DlgClient3.0.lib

all: core link r

core:
	@icl.exe /nologo /I$(PROJECT_INCLUDE_PATH)/ $(CLFL_BUILD_$(PROJECT_BUILD)) /c source/source/*.c /Fo:$(PROJECT_OBJECT_PATH)/

link:
	@xilink.exe /NOLOGO /TIME $(LDFL_BUILD_$(PROJECT_BUILD)) /MAP:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/ClientTest.map /PDB:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/ClientTest.pdb /OUT:$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/ClientTest.exe \
	$(PROJECT_OBJECT_PATH)/*.obj \

r:
	"$(PROJECT_BIN_PATH)/$(PROJECT_BUILD)/ClientTest.exe"
