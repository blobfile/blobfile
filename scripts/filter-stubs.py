"""
Hacky script to export type stubs for the purpose of creating public type information that pyright
can use
"""


import ast
import os
import argparse
import astor
import collections
import sys

assert sys.version_info >= (3, 8), "Python 3.8 or newer required to run this script"

# https://github.com/microsoft/pyright/issues/377

# expectations:
# this operates only on the root dir of a package
# __init__.py may only contains imports from other modules
#   __init__.py will be copied directly to __init__.pyi
# all exported symbols must be imported in __init__.py (this applies to nested modules as well, __init__.py must import those)
#
# supported import styles:
#   from .modulename import symbol1, symbol2
#   from . import package

HEADER = """\
# This file was generated automatically by filter-stubs.py

"""


Define = collections.namedtuple("Define", ["name", "text", "locals", "imports"])
Import = collections.namedtuple("Import", ["kind", "module", "name", "asname"])


def find_symbols(node, symbol_name_to_import):
    result = []
    if isinstance(node, ast.Name):
        result.append(node.id)
    elif isinstance(node, ast.Attribute):
        n = node
        path_parts = []
        while True:
            if isinstance(n, ast.Attribute):
                path_parts.append(n.attr)
            elif isinstance(n, ast.Name):
                path_parts.append(n.id)
                break
            elif isinstance(n, ast.Call):
                break
            else:
                raise Exception(f"unrecognized node {n}: {astor.to_source(n)}")
            n = n.value
        path = ".".join(path_parts[::-1])
        result.append(path)
    elif isinstance(node, ast.Subscript):
        result.extend(find_symbols(node.value, symbol_name_to_import))
        if isinstance(node.slice.value, ast.Tuple):
            for elt in node.slice.value.elts:
                result.extend(find_symbols(elt, symbol_name_to_import))
        else:
            result.extend(find_symbols(node.slice.value, symbol_name_to_import))
    elif isinstance(node, ast.Call):
        result.extend(find_symbols(node.func, symbol_name_to_import))
        for arg in node.args:
            result.extend(find_symbols(arg, symbol_name_to_import))
        for keyword in node.keywords:
            result.extend(find_symbols(keyword.value, symbol_name_to_import))
    return result


def get_prefixes(name):
    parts = name.split(".")
    current = []
    result = []
    for part in parts:
        current.append(part)
        result.append(".".join(current))
    return result


def group_symbols(symbols, symbol_name_to_import):
    local = []
    imported = []
    for name in symbols:
        if name not in dir(__builtins__):
            for prefix in get_prefixes(name):
                if prefix in symbol_name_to_import:
                    imported.append(prefix)
                    break
            else:
                local.append(name)
    return local, imported


def get_locals_and_imports(node, symbol_name_to_import):
    symbols = find_symbols(node, symbol_name_to_import)
    local_symbols, imported_symbols = group_symbols(symbols, symbol_name_to_import)
    exports = local_symbols
    imports = []
    for name in imported_symbols:
        imports.append(symbol_name_to_import[name])
    return exports, imports


def node_to_defines(node, symbol_name_to_import):
    if isinstance(node, ast.FunctionDef):
        if node.name.startswith("_"):
            return []

        all_imports = []
        define_text = ""
        if len(node.decorator_list) == 1 and node.decorator_list[0].id == "overload":
            define_text += "@overload\n"
            all_imports.append(symbol_name_to_import["overload"])

        define_text += f"def {node.name}("
        define_args = []
        func_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        defaults = node.args.defaults + node.args.kw_defaults
        all_locals = []
        for arg_index, arg in enumerate(func_args):
            arg_locals, arg_imports = get_locals_and_imports(
                arg.annotation, symbol_name_to_import
            )
            all_imports.extend(arg_imports)
            all_locals.extend(arg_locals)
            arg_str = f"{arg.arg}"
            if arg.annotation is not None:
                arg_str += f": {astor.to_source(arg.annotation).strip()}"
            if arg_index >= len(func_args) - len(defaults):
                arg_str += "=..."
            define_args.append(arg_str)
        define_text += ", ".join(define_args)
        if node.returns is None:
            define_text += f"):"
            # had to remove return value of BlobFile to fix pyright error
            # but then this error is raised
            # raise Exception(
            #     f"definition missing return type: {astor.to_source(node).strip()}"
            # )
        else:
            define_text += f") -> {astor.to_source(node.returns).strip()}:"
        returns_locals, returns_imports = get_locals_and_imports(
            node.returns, symbol_name_to_import
        )
        all_locals.extend(returns_locals)
        all_imports.extend(returns_imports)
        define_text += "\n  ..."
        return [
            Define(
                name=node.name, text=define_text, locals=all_locals, imports=all_imports
            )
        ]
    elif isinstance(node, ast.Assign) or isinstance(node, ast.AnnAssign):
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1:
                target = node.targets[0]
            else:
                return []
        else:
            target = node.target

        if isinstance(target, ast.Name):
            assign_locals, assign_imports = get_locals_and_imports(
                node.value, symbol_name_to_import
            )
            if isinstance(node, ast.AnnAssign):
                locs, imps = get_locals_and_imports(
                    node.annotation, symbol_name_to_import
                )
                assign_locals.extend(locs)
                assign_imports.extend(imps)
            if target.id.startswith("_"):
                return []
            return [
                Define(
                    name=target.id,
                    text=astor.to_source(node).strip(),
                    locals=assign_locals,
                    imports=assign_imports,
                )
            ]
    else:
        return []


def indent(text):
    lines = []
    for line in text.split("\n"):
        lines.append("  " + line)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stubspath", required=True)
    parser.add_argument("--outputpath", required=True)
    args = parser.parse_args()

    root_path = os.path.dirname(os.path.abspath(args.stubspath))

    for base, dirnames, filenames in os.walk(args.stubspath):
        assert isinstance(base, str)

        relpath = os.path.relpath(base, root_path)
        package_path = relpath.split(os.path.sep)

        if "__init__.pyi" not in filenames:
            # not a python package
            continue

        # scan __init__.py to gather all exported symbols
        module_name_to_exported_symbol_names = collections.defaultdict(list)
        packages_to_walk = []

        init_path = os.path.join(base, "__init__.pyi")
        with open(init_path, "r") as f:
            init_contents = f.read()
            root = ast.parse(init_contents)
            for node in ast.iter_child_nodes(root):
                if isinstance(node, ast.ImportFrom):
                    if node.module is None:
                        print(
                            f"ignoring relative import: `{astor.to_source(node).strip()}` in {init_path}"
                        )
                    else:
                        if node.level == 0:
                            import_path = node.module.split(".")
                            if (
                                len(import_path) == len(package_path) + 1
                                and import_path[:-1] == package_path
                            ):
                                module_name = import_path[-1]
                                module_path = os.path.join(root_path, *import_path)
                                if os.path.isdir(module_path) and os.path.exists(
                                    os.path.join(module_path, "__init__.py")
                                ):
                                    packages_to_walk.append(module_name)
                                for alias in node.names:
                                    module_name_to_exported_symbol_names[
                                        module_name
                                    ].append(alias.name)
                        elif node.level == 1:
                            print(
                                f"ignoring multi-level relative import: `{astor.to_source(node).strip()}` in {init_path}"
                            )
                        else:
                            print(
                                f"ignoring multi-level relative import: `{astor.to_source(node).strip()}` in {init_path}"
                            )

        # only explore packages that have been marked as exported
        dirnames[:] = packages_to_walk

        if len(module_name_to_exported_symbol_names) == 0:
            raise Exception("no exported symbols found")

        module_name_to_public_symbol_definitions = {}
        module_name_to_imports = {}
        for filename in filenames:
            assert isinstance(filename, str)

            if (
                not filename.endswith(".pyi")
                or filename == "__init__.pyi"
                or filename.startswith("test_")
                or filename.endswith("_test.pyi")
            ):
                continue

            filepath = os.path.join(base, filename)
            print(f"processing {filepath}")
            with open(filepath, "r") as f:
                root = ast.parse(f.read())

                symbol_name_to_import = {}
                module_name = os.path.splitext(os.path.basename(filename))[0]
                defines = collections.defaultdict(list)
                for node in ast.iter_child_nodes(root):
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            symbol_name_to_import[alias.name] = Import(
                                kind="from",
                                module=node.module,
                                name=alias.name,
                                asname=alias.asname,
                            )
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            symbol_name_to_import[alias.name] = Import(
                                kind="direct",
                                module=alias.name,
                                name=None,
                                asname=alias.asname,
                            )
                    elif (
                        isinstance(node, ast.FunctionDef)
                        or isinstance(node, ast.AnnAssign)
                        or isinstance(node, ast.Assign)
                    ):
                        for define in node_to_defines(node, symbol_name_to_import):
                            defines[define.name].append(define)
                    elif isinstance(node, ast.ClassDef):
                        if node.name.startswith("_"):
                            continue

                        class_locals = []
                        class_imports = []
                        bases = []
                        for class_base in node.bases:
                            bases.append(astor.to_source(class_base).strip())
                            locs, imps = get_locals_and_imports(
                                class_base, symbol_name_to_import
                            )
                            class_locals.extend(locs)
                            class_imports.extend(imps)

                        for body_node in node.body:
                            for define in node_to_defines(
                                body_node, symbol_name_to_import
                            ):
                                class_locals.extend(define.locals)
                                class_imports.extend(define.imports)
                        defines[node.name].append(
                            Define(
                                name=node.name,
                                text=astor.to_source(node),
                                locals=class_locals,
                                imports=class_imports,
                            )
                        )

                module_name_to_imports[module_name] = symbol_name_to_import.values()
                module_name_to_public_symbol_definitions[module_name] = defines

        relpath = os.path.relpath(base, args.stubspath)
        output_base = os.path.join(args.outputpath, relpath)
        assert isinstance(output_base, str)
        with open(os.path.join(output_base, "__init__.pyi"), "w") as f:
            print(f"writing {f.name}")
            f.write(HEADER)
            f.write(init_contents)

        for (
            module_name,
            symbol_definitions,
        ) in module_name_to_public_symbol_definitions.items():
            exported_symbols = module_name_to_exported_symbol_names[module_name][:]
            while True:
                exported_symbols_length = len(exported_symbols)
                for exported_name in exported_symbols:
                    if exported_name in symbol_definitions:
                        defines = symbol_definitions[exported_name]
                        for define in defines:
                            for local in define.locals:
                                if local not in exported_symbols:
                                    exported_symbols.insert(0, local)
                if exported_symbols_length == len(exported_symbols):
                    # we didn't add any new symbols this loop, we're done here
                    break

            all_imports = module_name_to_imports[module_name]

            exported_defines = []
            for exported_name in exported_symbols:
                if exported_name not in symbol_definitions:
                    print("MISSING exported symbol", exported_name)
                    continue
                for define in symbol_definitions[exported_name]:
                    exported_defines.append(define)

            with open(os.path.join(output_base, f"{module_name}.pyi"), "w") as f:
                print(f"writing {f.name}")
                f.write(HEADER)
                for imp in all_imports:
                    if imp.kind == "from":
                        if imp.asname is None:
                            f.write(f"from {imp.module} import {imp.name}\n")
                        else:
                            f.write(
                                f"from {imp.module} import {imp.name} as {imp.asname}\n"
                            )
                    elif imp.kind == "direct":
                        if imp.asname is None:
                            f.write(f"import {imp.module}\n")
                        else:
                            f.write(f"import {imp.module} as {imp.asname}\n")

                    else:
                        raise Exception(f"unrecognized import kind {imp.kind}")
                for define in exported_defines:
                    f.write(define.text + "\n")


if __name__ == "__main__":
    main()
