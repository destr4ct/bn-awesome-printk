import ctypes
import binaryninja as bn
from binaryninja import BinaryView as bv
from binaryninja.binaryview import ReferenceSource

plugin_header = '[d4printk]:'

sym_variations = [
	'printk',
	'_printk',
	'__printk'
]

START_OF_HEADER = 1

MSG_TYPE = {
	'0': 'KERN_EMERG',
	'1': 'KERN_ALERT',
	'2': 'KERN_CRIT',
	'3': 'KERN_ERR',
	'4': 'KERN_WARNING',
	'5': 'KERN_NOTICE',
	'6': 'KERN_INFO',
	'7': 'KERN_DEBUG',
}

HEADER_SZ = 12


def get_printk_addr(bv: bv):
	global sym_variations

	for v in sym_variations:
		sym = bv.get_symbol_by_raw_name(v)
		if sym:
			return sym.address

	return print(f'{plugin_header} printk not found?')


def get_printk_refs(bv: bv, addr):
	return [ref for ref in bv.get_code_refs(addr)]


def pretty_print_refs(refs):
	print(f'{plugin_header} printk refs:')

	for ref in refs:
		print(f'\tADDR: {hex(ref.address)}')


def force_change(instance, field, value):
    # Use the `object.__dict__` directly to modify the attribute
    try:
        instance.__dict__[field] = value
    except AttributeError:
        # If the direct dictionary access fails (common with slots or frozen dataclasses)
        # Use a more forceful method
        for cls in type(instance).__mro__:
            if field in cls.__dict__:
                # Bypass the property or descriptor directly
                object.__setattr__(instance, field, value)
                break
        else:
            # If all else fails, log that no such attribute exists
            print(f"No attribute {field} found in {type(instance).__name__} or its superclasses.")

def patch_printk_ref(bv: bv, ref: ReferenceSource, addr):	
	mil = ref.function.medium_level_il
	lil = ref.function.low_level_il
	br = bn.BinaryReader(bv)

	
	# Search for MediumLevelILCall
	for mil_instr in mil.instructions:
		if isinstance(mil_instr, bn.mediumlevelil.MediumLevelILCall):
			call_params = mil_instr.params					

			# Then it's real printk call and 0 arg is fmt
			if mil_instr.dest.value == addr and len(call_params) > 0:
				
				rpp      = call_params[0]
				fmt_addr = rpp.value
				
				# Seek to arg address and read header
				br.seek(fmt_addr)
				fmt_header = br.read(HEADER_SZ)

				if len(fmt_header) > 1 and fmt_header[0] == START_OF_HEADER:
					# Next byte will be header
					header_byte = chr(fmt_header[1])

					if header_byte in MSG_TYPE:
						k_msg_t = MSG_TYPE[header_byte]

						while True:
							nc = br.read(HEADER_SZ)
							fmt_header += nc 

							if b'\x00' in nc:
								fmt_header = fmt_header[2:fmt_header.index(b'\x00')]
								break
						
						fmt_header = fmt_header.decode()
						fmt_header.rstrip('\n')

						ref.function.set_comment_at(mil_instr.address, f'MSG: {k_msg_t} {fmt_header}')
						
						# TODO: patch M_IL
						# mil_instr.function.generate_ssa_form()

					else:
						print(f'{plugin_header} bad header: {header_byte}!')


def patch_printk(bv: bv):
	addr = get_printk_addr(bv)
	if not addr:
		return

	refs = get_printk_refs(bv, addr)
	pretty_print_refs(refs)

	print(f'{plugin_header} patching everything...')
	for ref in refs:
		patch_printk_ref(bv, ref, addr)


	print(f'{plugin_header} done!')