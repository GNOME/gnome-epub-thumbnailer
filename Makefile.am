
bin_PROGRAMS = gnome-epub-thumbnailer gnome-mobi-thumbnailer

gnome_epub_thumbnailer_SOURCES = gnome-epub-thumbnailer.c gnome-thumbnailer-skeleton.c gnome-thumbnailer-skeleton.h
gnome_epub_thumbnailer_CPPFLAGS =			\
	$(THUMBNAILER_CFLAGS)				\
	-DTHUMBNAILER_RETURNS_DATA			\
	-DTHUMBNAILER_USAGE="\"Thumbnail EPub books\""	\
	$(WARN_CFLAGS)
gnome_epub_thumbnailer_LDADD = $(THUMBNAILER_LIBS)

gnome_mobi_thumbnailer_SOURCES = gnome-mobi-thumbnailer.c gnome-thumbnailer-skeleton.c gnome-thumbnailer-skeleton.h
gnome_mobi_thumbnailer_CPPFLAGS =			\
	$(THUMBNAILER_CFLAGS)				\
	-DTHUMBNAILER_RETURNS_DATA			\
	-DTHUMBNAILER_USAGE="\"Thumbnail MOBI books\""	\
	$(WARN_CFLAGS)
gnome_mobi_thumbnailer_LDADD = $(THUMBNAILER_LIBS)

thumbnailerdir = $(datadir)/thumbnailers/
thumbnailer_DATA = gnome-epub-thumbnailer.thumbnailer gnome-mobi-thumbnailer.thumbnailer
gnome-epub-thumbnailer.thumbnailer: gnome-epub-thumbnailer.thumbnailer.in Makefile
	$(AM_V_GEN) $(SED) -e "s|\@bindir\@|$(bindir)|" $< > $@
gnome-mobi-thumbnailer.thumbnailer: gnome-mobi-thumbnailer.thumbnailer.in Makefile
	$(AM_V_GEN) $(SED) -e "s|\@bindir\@|$(bindir)|" $< > $@

EXTRA_DIST = gnome-epub-thumbnailer.thumbnailer.in gnome-mobi-thumbnailer.thumbnailer.in AUTHORS COPYING README

CLEANFILES = $(thumbnailer_DATA)
