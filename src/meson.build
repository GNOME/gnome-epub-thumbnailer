add_global_arguments('-DTHUMBNAILER_RETURNS_DATA', language : 'c')
prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
thumbnailers_dir = prefix / get_option('datadir') / 'thumbnailers'

foreach file_format : ['EPub', 'MOBI']
  exec_name = 'gnome-@0@-thumbnailer'.format(file_format.to_lower())
  executable(exec_name,
             exec_name + '.c', 'gnome-thumbnailer-skeleton.c',
             c_args : '-DTHUMBNAILER_USAGE=' + '"Thumbnail @0@ books"'.format(file_format),
             dependencies : deps,
             install : true)
  configure_file(input : exec_name + '.thumbnailer.in',
                 output : exec_name + '.thumbnailer',
                 configuration : {'bindir' : bindir},
                 install_dir : thumbnailers_dir)
endforeach
