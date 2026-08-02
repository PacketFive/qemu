subdir('bench')
subdir('qemu-iotests')

test_qapi_outputs = [
  'qapi-builtin-types.c',
  'qapi-builtin-types.h',
  'qapi-builtin-visit.c',
  'qapi-builtin-visit.h',
  'test-qapi-commands-sub-sub-module.c',
  'test-qapi-commands-sub-sub-module.h',
  'test-qapi-commands.c',
  'test-qapi-commands.h',
  'test-qapi-emit-events.c',
  'test-qapi-emit-events.h',
  'test-qapi-events-sub-sub-module.c',
  'test-qapi-events-sub-sub-module.h',
  'test-qapi-events.c',
  'test-qapi-events.h',
  'test-qapi-features.c',
  'test-qapi-features.h',
  'test-qapi-init-commands.c',
  'test-qapi-init-commands.h',
  'test-qapi-introspect.c',
  'test-qapi-introspect.h',
  'test-qapi-types-sub-sub-module.c',
  'test-qapi-types-sub-sub-module.h',
  'test-qapi-types.c',
  'test-qapi-types.h',
  'test-qapi-visit-sub-sub-module.c',
  'test-qapi-visit-sub-sub-module.h',
  'test-qapi-visit.c',
  'test-qapi-visit.h',
]

# Problem: to generate trace events, we'd have to add the .trace-events
# file to qapi_trace_events like we do in qapi/meson.build.  Since
# qapi_trace_events is used by trace/meson.build, we'd have to move
# subdir('tests') above subdir('trace') in the top-level meson.build.
# Can't, because it would break the dependency of qga on qemuutil (which
# depends on trace_ss).  Not worth solving now; simply suppress trace
# event generation instead.
test_qapi_files = custom_target('Test QAPI files',
                                output: test_qapi_outputs,
                                input: files('qapi-schema/qapi-schema-test.json',
                                             'qapi-schema/include/sub-module.json',
                                             'qapi-schema/sub-sub-module.json'),
                                command: [ qapi_gen, '-o', meson.current_build_dir(),
                                           '-b', '-p', 'test-', '@INPUT0@',
                                           '--suppress-tracing' ],
                                depend_files: qapi_gen_depends)

# meson doesn't like generated output in other directories
# perhaps change qapi_gen to replace / with _, like Meson itself does?
subdir('include')

test_qapi_sources = []
test_qapi_headers = []
i = 0
foreach o: test_qapi_files.to_list() + test_qapi_files_extra.to_list()
  if o.full_path().endswith('.h')
    test_qapi_headers += o
  endif
  test_qapi_sources += o
endforeach

libtestqapi = static_library('testqapi', sources: [genh, test_qapi_sources])
testqapi = declare_dependency(link_with: libtestqapi, sources: [genh, test_qapi_headers])

test_deps = {
  'test-qht-par': qht_bench,
}

if have_tools and have_vhost_user and host_os == 'linux'
  executable('vhost-user-bridge',
             sources: files('vhost-user-bridge.c'),
             dependencies: [qemuutil, vhost_user])
endif

subdir('decode')

if 'CONFIG_TCG' in config_all_accel
  subdir('fp')
  subdir('tcg/plugins')
endif

subdir('unit')
subdir('qapi-schema')
subdir('qtest')
subdir('migration-stress')
subdir('functional')

# PDP-12 (PDP-V) target tests. Each script drives qemu-system-pdp12 over QMP
# and checks architectural state against the reference emulator or the
# normative profiles.
if 'pdp12-softmmu' in target_dirs
  pdp12_emulator = emulators['qemu-system-pdp12']
  pdp12_node = find_program('node', required: false)
  pdp12_tests = {
    'pdp12-differential-test.py': 600,
    'pdp12-scalar-test.py': 600,
    'pdp12-atomic-test.py': 600,
    'pdp12-privileged-test.py': 600,
    'pdp12-p39-test.py': 600,
    'pdp12-direct-kernel-smoke.py': 180,
    'pdp12-boot-rom-smoke.py': 120,
  }
  if pdp12_node.found()
    # The linked-head smoke builds its kernel image with the Node reference
    # emulator's linker.
    pdp12_tests += {'pdp12-linux-head-smoke.py': 300}
  endif
  foreach script, seconds : pdp12_tests
    test(script.split('.')[0],
         python,
         args: [meson.current_source_dir() / script,
                pdp12_emulator.full_path()],
         depends: [pdp12_emulator],
         timeout: seconds,
         priority: seconds,
         suite: ['pdp12'])
  endforeach
endif
