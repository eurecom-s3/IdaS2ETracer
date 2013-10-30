AM_CXXFLAGS = -I$(top_srcdir)/s2e/ -I$(top_srcdir)

lib_LTLIBRARIES = libidas2etracer.la
libidas2etracer_la_SOURCES = IdaTracer.cpp IdaTracer.h PluginEntry.cpp
libidas2etracer_la_LIBADD = $(top_srcdir)/s2e/libs2etools.la
libidas2etracer_la_LDFLAGS = -lida -avoid-version -shrext '.plx' -no-install
