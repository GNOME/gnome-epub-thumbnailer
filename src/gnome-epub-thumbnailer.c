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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include <string.h>
#include <glib.h>

#include "gnome-thumbnailer-skeleton.h"

#include <archive.h>
#include <archive_entry.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define METAFILE_NAMESPACE "urn:oasis:names:tc:opendocument:xmlns:container"
#define OPF_NAMESPACE "http://www.idpf.org/2007/opf"

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
		g_print ("Failed to open archive %s\n", filename);
		return NULL;
	}

	while (1) {
		const char *name;

		r = archive_read_next_header(a, &entry);

		if (r != ARCHIVE_OK) {
			if (r != ARCHIVE_EOF && r == ARCHIVE_FATAL)
				g_warning ("Fatal error handling archive: %s", archive_error_string (a));
			break;
		}

		name = archive_entry_pathname (entry);
		if (func (name, user_data) == 0) {
			size_t size = archive_entry_size (entry);
			char *buf;
			ssize_t read;

			buf = g_malloc (size);
			read = archive_read_data (a, buf, size);
			if (read <= 0) {
				g_free (buf);
				if (read < 0)
					g_warning ("Fatal error reading '%s' in archive: %s", name, archive_error_string (a));
				else
					g_warning ("Read an empty file from the archive");
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
	if (g_strcmp0(".", dirname) != 0)
		ret = g_build_filename (dirname, cover_path, NULL);
	else
		ret = g_strdup(cover_path);
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
	g_autofree char *root_path = NULL;
	g_autofree char *root_file = NULL;
	gsize root_length;
	char *cover_path, *full_cover_path;

	cover_path = NULL;

	root_path = get_root_file_from_metafile (metafile, length);
	if (!root_path) {
		g_warning ("Couldn't get root path for metafile %s", metafile);
		return NULL;
	}

	g_debug ("Got root path '%s' from metafile", root_path);
	root_file = file_get_zipped_contents (input_filename, (GCompareFunc) g_strcmp0, root_path, &root_length);
	if (root_file != NULL)
		g_debug ("#### '%s' contents ####\n%s", root_path, root_file);

	doc = open_doc (root_file, root_length, "package");
	if (!doc)
		return NULL;

	xpath_ctx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs (xpath_ctx, BAD_CAST ("ns"), BAD_CAST (OPF_NAMESPACE));

	/* Look for "cover-image" manifest item property
	 * https://www.w3.org/publishing/epub3/epub-packages.html#sec-item-property-values */
	cover_path = get_prop_for_xpath (doc, xpath_ctx, "//ns:package/ns:manifest/ns:item[@properties='cover-image']", "href");

	if (!cover_path) {
		g_autofree char *xpath = NULL;
		g_autofree char *content_name = NULL;

		content_name = get_prop_for_xpath (doc, xpath_ctx, "//ns:package/ns:metadata/ns:meta[@name='cover']", "content");
		if (!content_name)
			goto bail;
		g_debug ("Found content_name '%s'", content_name);

		xpath = g_strdup_printf ("//ns:package/ns:manifest/ns:item[@id='%s']", content_name);
		cover_path = get_prop_for_xpath (doc, xpath_ctx, xpath, "href");
		if (!cover_path)
			cover_path = g_strdup (content_name);
	}

	g_debug ("Found cover_path '%s'", cover_path);
	if (!cover_path)
		goto bail;

	full_cover_path = resolve_cover_path (cover_path, root_path);
	g_free (cover_path);
	cover_path = full_cover_path;
	g_debug ("Resolved full_cover_path '%s'", cover_path);

bail:
	xmlXPathFreeContext(xpath_ctx);
	xmlFreeDoc (doc);

	return cover_path;
}

char *
file_to_data (const char  *path,
	      gsize       *ret_length,
	      GError     **error)
{
	g_autofree char *metafile = NULL;
	g_autofree char *cover_path = NULL;
	gsize length;
	char *cover_data = NULL;

	/* Look for the cover in the metafile */
	metafile = file_get_zipped_contents (path, (GCompareFunc) g_strcmp0, "META-INF/container.xml", &length);
	if (metafile == NULL) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Could not find META-INF/container.xml file");
		return NULL;
	}
	g_debug ("#### META-INF/container.xml contents ####\n %s", metafile);
	cover_path = get_cover_path_from_root_file (metafile, length, path);
	if (cover_path != NULL) {
		cover_data = file_get_zipped_contents (path, (GCompareFunc) g_strcmp0, cover_path, &length);
		if (cover_data == NULL)
			g_warning ("Could not open cover file '%s' in '%s'",
				   cover_path, path);
	}

	/* Look for it by name instead */
	if (cover_data == NULL) {
		GRegex *regex;

		regex = g_regex_new (".*(cover|couv).*\\.(jpg|jpeg|png|svg)",
				     G_REGEX_CASELESS, 0, NULL);
		cover_data = file_get_zipped_contents (path, regex_matches, regex, &length);
	}

	if (cover_data == NULL) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Could not find cover file");
		return NULL;
	}

	*ret_length = length;

	return cover_data;
}
