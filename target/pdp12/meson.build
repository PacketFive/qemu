pdp12_ss = ss.source_set()
pdp12_system_ss = ss.source_set()
pdp12_common_system_ss = ss.source_set()

pdp12_ss.add(files(
  'cpu.c',
  'translate.c',
  'mmu.c',
))

target_arch += {'pdp12': pdp12_ss}
target_system_arch += {'pdp12': pdp12_system_ss}
target_common_system_arch += {'pdp12': pdp12_common_system_ss}
