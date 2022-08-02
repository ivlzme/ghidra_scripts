# Recover struct data types that are passed by pointer to functions as parameters.
# Utilizes the Ghidra "Auto create structure" feature to perform the recovery
# analysis (FillOutStructureCmd.java).
#
# TODO: this script will create duplicate structs if it has already been run. If a function
# parameter already has a user defined type, do not create a new struct data type.
# @author: achin
# @category: Struct Recovery

# Ghidra uses Jython which is stuck on Python 2.7 :(
# Do this for more python3-esque prints
from __future__ import print_function

from ghidra.app.decompiler import DecompInterface
from ghidra.app.plugin.core.decompile.actions import FillOutStructureCmd
from ghidra.program.model.data import PointerDataType, DataTypeConflictHandler
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.util import ProgramLocation


def decompiler_apply_struct(struct, hv):
    """Apply the recovered struct parameter to the function decompiler listing.
    The data type should be applied following the data flow graph of this
    function.

    :param struct: recovered Ghidra structure type
    :param hv: Ghidra high variable representing the function parameter
    """
    ptr_dt = PointerDataType(struct)
    dt_mgr = currentProgram.getDataTypeManager()
    ptr_dt = dt_mgr.addDataType(ptr_dt, DataTypeConflictHandler.DEFAULT_HANDLER)
    HighFunctionDBUtil.updateDBVariable(hv.getSymbol(), None, ptr_dt, SourceType.USER_DEFINED)


def analyze_function(di, func):
    """Analyze a function's parameters for struct data types. If any are found,
    apply them to the decompiler listing

    :param di: Ghidra decompiler interface
    :param func: Ghidra function to analyze
    """
    print('Analyzing function {}'.format(func.getName()))

    res = di.decompileFunction(func, 0, monitor)
    if res.decompileCompleted():
        # Get function parameters according to decompiler result
        high_func = res.getHighFunction()
        func_proto = high_func.getFunctionPrototype()
        params = [func_proto.getParam(i) for i in range(func_proto.getNumParams())]
        print('    params: {}'.format(len(params)))
        for p_high_sym in params:
            # Use Ghidra's "Auto create structure" analysis
            param_loc = ProgramLocation(currentProgram, p_high_sym.getPCAddress())
            fill_cmd = FillOutStructureCmd(currentProgram, param_loc, state.getTool())
            high_var = p_high_sym.getHighVariable()
            struct = fill_cmd.processStructure(high_var, func)

            # Don't apply recovered structs that are not actually structs
            if not struct or struct.getLength() == 0 or struct.getNumComponents() < 2:
                continue

            print('    Found struct ({} bytes, {} members)'.format(struct.getLength(), struct.getNumComponents()))
            decompiler_apply_struct(struct, high_var)


def get_all_functions():
    """Return a list of all non-external functions in the program

    :return: Python list of Ghidra functions
    """
    fm = currentProgram.getFunctionManager()
    return [f for f in fm.getFunctions(True)]


def main():
    """Main driver function
    """
    di = DecompInterface()
    di.openProgram(currentProgram)

    for f in get_all_functions():
        analyze_function(di, f)


if __name__ == "__main__":
    main()
