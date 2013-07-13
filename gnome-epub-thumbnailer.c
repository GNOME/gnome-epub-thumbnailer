/*
 * Copyright (C) 2013 Bastien Nocera <hadess@hadess.net>
 *
 * Authors: Bastien Nocera <hadess@hadess.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <gdk-pixbuf/gdk-pixbuf.h>

#include <archive.h>
#include <archive_entry.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define METAFILE_NAMESPACE "urn:oasis:names:tc:opendocument:xmlns:container"
#define OPF_NAMESPACE "http://www.idpf.org/2007/opf"

static int output_size = 256;
static gboolean g_fatal_warnings = FALSE;
static char **filenames = NULL;

static const GOptionEntry entries[] = {
	{ "size", 's', 0, G_OPTION_ARG_INT, &output_size, "Size of the thumbnail in pixels", NULL },
	{"g-fatal-warnings", 0, 0, G_OPTION_ARG_NONE, &g_fatal_warnings, "Make all warnings fatal", NULL},
	{ G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_FILENAME_ARRAY, &filenames, NULL, "[FILE...]" },
	{ NULL }
};

static int
regex_matches (gconstpointer a,
	       gconstpointer b)
{
	const char *path = a;
	GRegex *regex = (GRegex *) b;

	if (g_regex_match (regex, path, 0, NULL))
		return 0;
	return -1;
}

static char *
file_get_zipped_contents (const char   *filename,
			  GCompareFunc  func,
			  gpointer      user_data,
			  gsize        *length)
{
	struct archive *a;
	struct archive_entry *entry;
	char *ret = NULL;
	int r;

	*length = 0;

	a = archive_read_new ();
	archive_read_support_format_zip (a);
	r = archive_read_open_filename (a, filename, 10240);
	if (r != ARCHIVE_OK) {
		g_print ("Failed to open archive %s\n", filenames[0]);
		return NULL;
	}

	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		const char *name;

		name = archive_entry_pathname (entry);
		if (func (name, user_data) == 0) {
			size_t size = archive_entry_size (entry);
			char *buf;
			ssize_t read;

			buf = g_malloc (size);
			read = archive_read_data (a, buf, size);
			if (read <= 0) {
				g_free (buf);
			} else {
				ret = buf;
				*length = size;
			}
			break;
		}
		archive_read_data_skip(a);
	}
	archive_read_free(a);

	return ret;
}

static xmlDocPtr
open_doc (const char *data,
	  gsize       length,
	  const char *root_name)
{
	xmlDocPtr doc;

	if (data == NULL)
		return NULL;

	doc = xmlParseMemory (data, length);
	if (doc == NULL)
		doc = xmlRecoverMemory (data, length);

	if(!doc ||
	   !doc->children ||
	   !doc->children->name ||
	   g_ascii_strcasecmp ((char *)doc->children->name, root_name) != 0) {
		if (doc != NULL)
			xmlFreeDoc (doc);
		return NULL;
	}

	return doc;
}

static char *
get_prop_for_xpath (xmlDocPtr           doc,
		    xmlXPathContextPtr  xpath_ctx,
		    const char         *path,
		    const char         *name)
{
	xmlXPathObjectPtr xpath_obj;
	xmlNodePtr cur;
	char *ret = NULL;

	xpath_obj = xmlXPathEvalExpression (BAD_CAST (path), xpath_ctx);
	if (xpath_obj == NULL)
		return NULL;
	if (xpath_obj->nodesetval == NULL ||
	    xpath_obj->nodesetval->nodeTab == NULL)
		goto bail;
	cur = xpath_obj->nodesetval->nodeTab[0];
	if (cur != NULL) {
		xmlChar *prop;

		prop = xmlGetProp (cur, BAD_CAST (name));
		if (prop) {
			ret = g_strdup ((const char *) prop);
			xmlFree (prop);
		}
	}

bail:
	xmlXPathFreeObject (xpath_obj);

	return ret;
}

static char *
get_root_file_from_metafile (const char *metafile,
			     gsize       length)
{
	char *root_file;
	xmlDocPtr doc;
	xmlXPathContextPtr xpath_ctx;

	doc = open_doc (metafile, length, "container");
	if (!doc)
		return NULL;

	xpath_ctx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs (xpath_ctx, BAD_CAST ("ns"), BAD_CAST (METAFILE_NAMESPACE));

	root_file = get_prop_for_xpath (doc, xpath_ctx, "//ns:container/ns:rootfiles/ns:rootfile", "full-path");

	xmlXPathFreeContext(xpath_ctx);
	xmlFreeDoc (doc);

	return root_file;
}

static char *
resolve_cover_path (const char *cover_path,
		    const char *root_path)
{
	char *dirname;
	char *ret;

	dirname = g_path_get_dirname (root_path);
	ret = g_build_filename (dirname, cover_path, NULL);
	g_free (dirname);

	return ret;
}

static char *
get_cover_path_from_root_file (const char *metafile,
			       gsize       length,
			       const char *input_filename)
{
	xmlDocPtr doc;
	xmlXPathContextPtr xpath_ctx;
	char *root_path;
	char *root_file;
	gsize root_length;
	char *content_name;
	char *xpath;
	char *cover_path, *full_cover_path;

	cover_path = NULL;

	root_path = get_root_file_from_metafile (metafile, length);
	if (!root_path)
		return NULL;

	root_file = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, root_path, &root_length);

	doc = open_doc (root_file, root_length, "package");
	g_free (root_file);
	if (!doc) {
		g_free (root_path);
		return NULL;
	}

	xpath_ctx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs (xpath_ctx, BAD_CAST ("ns"), BAD_CAST (OPF_NAMESPACE));

	content_name = get_prop_for_xpath (doc, xpath_ctx, "//ns:package/ns:metadata/ns:meta[@name='cover']", "content");
	if (!content_name)
		goto bail;

	xpath = g_strdup_printf ("//ns:package/ns:manifest/ns:item[@id='%s']", content_name);
	g_free (content_name);
	cover_path = get_prop_for_xpath (doc, xpath_ctx, xpath, "href");
	g_free (xpath);

	full_cover_path = resolve_cover_path (cover_path, root_path);
	g_free (cover_path);
	cover_path = full_cover_path;

bail:
	g_free (root_path);
	xmlXPathFreeContext(xpath_ctx);
	xmlFreeDoc (doc);

	return cover_path;
}

int main (int argc, char **argv)
{
	char *input_filename;
	char *metafile;
	gsize length;
	char *cover_path;
	char *cover_data = NULL;
	GInputStream *mem_stream;

	GdkPixbuf *pixbuf;
	GError *error = NULL;
	GOptionContext *context;
	GFile *input;
	const char *output;

	g_type_init ();

	/* Options parsing */
	context = g_option_context_new ("Thumbnail EPub books");
	g_option_context_add_main_entries (context, entries, NULL);

	if (g_option_context_parse (context, &argc, &argv, &error) == FALSE) {
		g_warning ("Couldn't parse command-line options: %s", error->message);
		g_error_free (error);
		return 1;
	}

	/* Set fatal warnings if required */
	if (g_fatal_warnings) {
		GLogLevelFlags fatal_mask;

		fatal_mask = g_log_set_always_fatal (G_LOG_FATAL_MASK);
		fatal_mask |= G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL;
		g_log_set_always_fatal (fatal_mask);
	}

	if (filenames == NULL || g_strv_length (filenames) != 2) {
		g_print ("Expects an input and an output file\n");
		return 1;
	}

	input = g_file_new_for_commandline_arg (filenames[0]);
	input_filename = g_file_get_path (input);
	g_object_unref (input);

	output = filenames[1];

	/* Look for the cover in the metafile */
	metafile = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, "META-INF/container.xml", &length);
	cover_path = get_cover_path_from_root_file (metafile, length, input_filename);
	g_free (metafile);
	if (cover_path != NULL) {
		cover_data = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, cover_path, &length);
		if (cover_data == NULL)
			g_warning ("Could not open cover file '%s' in '%s'",
				   cover_path, filenames[0]);
		g_free (cover_path);
	}

	/* Look for it by name instead */
	if (cover_data == NULL) {
		GRegex *regex;

		regex = g_regex_new (".*cover.*\\.(jpg|jpeg|png)",
				     G_REGEX_CASELESS, 0, NULL);
		cover_data = file_get_zipped_contents (input_filename, regex_matches, regex, &length);
	}

	g_free (input_filename);

	if (cover_data == NULL) {
		g_warning ("Could not find cover file in '%s'", filenames[0]);
		return 1;
	}

	mem_stream = g_memory_input_stream_new_from_data (cover_data, length, g_free);
	pixbuf = gdk_pixbuf_new_from_stream_at_scale (mem_stream, output_size, -1, TRUE, NULL, NULL);
	g_object_unref (mem_stream);

	if (!pixbuf) {
		g_warning ("Couldn't open embedded cover image for file '%s'",
			   filenames[0]);
		return 1;
	}

	if (gdk_pixbuf_save (pixbuf, output, "png", &error, NULL) == FALSE) {
		g_warning ("Couldn't save the thumbnail '%s' for file '%s': %s", output, filenames[0], error->message);
		g_error_free (error);
		return 1;
	}

	g_object_unref (pixbuf);

	return 0;
}
