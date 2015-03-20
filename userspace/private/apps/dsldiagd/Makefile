EXE = dsldiagd
dynamic: generic_exe_install

clean:
	rm -f dsldiagd


dsldiagd:
	cp dsldiagd_$(PROFILE)_save dsldiagd

CURR_DIR := $(shell pwd)
BUILD_DIR := $(subst /userspace, /userspace,$(CURR_DIR))
BUILD_DIR := $(word 1, $(BUILD_DIR))
include $(BUILD_DIR)/make.common
