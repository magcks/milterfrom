# - Try to find Milter lib
#
# The following variables are defined
#
#  Milter_FOUND - system has Milter lib
#  Milter_INCLUDE_DIR - the Milter include directory
#  Milter_LIBRARY - the Milter library

find_path(Milter_INCLUDE_DIR libmilter/mfapi.h
	/usr/local/include
	/usr/include
	/opt/local/include
	/sw/local/include
	/sw/include
	NO_DEFAULT_PATH
)
find_library(Milter_LIBRARY
	NAMES "milter"
	PATHS
	~/Library/Frameworks
	/Library/Frameworks
	/usr/local/lib
	/usr/local/lib64
	/usr/lib
	/usr/lib64
	/opt/local/lib
	/sw/local/lib
	/sw/lib
)

set(Milter_FOUND FALSE)
if(Milter_INCLUDE_DIR AND Milter_LIBRARY)
	set(Milter_FOUND TRUE)
endif(Milter_INCLUDE_DIR AND Milter_LIBRARY)
