"""Build-time enforcement for trusted tenant-boundary construction."""

import argparse
import ast
from pathlib import Path

_INDETERMINATE_TRUSTED_ALIAS = "__cephas_indeterminate_trusted_boundary_alias__"


def _literal_container_index(expression: ast.expr) -> int | None:
    """Return a supported integer literal index, excluding booleans."""
    if isinstance(expression, ast.Constant):
        index = expression.value
    elif (
        isinstance(expression, ast.UnaryOp)
        and isinstance(expression.op, ast.USub)
        and isinstance(expression.operand, ast.Constant)
    ):
        index = -expression.operand.value
    else:
        return None
    return index if isinstance(index, int) and not isinstance(index, bool) else None


def _resolve_container_expression(
    expression: ast.expr,
    imported_symbols: dict[str, str | ast.expr | None],
) -> ast.Tuple | ast.List | None:
    """Resolve only literal tuple/list containers and literal nested indexing.

    Unsupported expressions are outside this static resolver's accepted grammar
    and are not treated as proof that a source module is safe.
    """
    if isinstance(expression, (ast.Tuple, ast.List)):
        return expression
    if isinstance(expression, ast.Name):
        mapped = imported_symbols.get(expression.id)
        return (
            _resolve_container_expression(mapped, imported_symbols)
            if isinstance(mapped, ast.expr)
            else None
        )
    if isinstance(expression, ast.Subscript):
        container = _resolve_container_expression(expression.value, imported_symbols)
        index = _literal_container_index(expression.slice)
        if container is None or index is None:
            return None
        if -len(container.elts) <= index < len(container.elts):
            selected = container.elts[index]
            return _resolve_container_expression(selected, imported_symbols)
    return None


def _storage_root_name(expression: ast.expr) -> str | None:
    """Return the root name for an attribute/subscript storage expression."""
    current = expression
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _resolve_imported_symbol(
    expression: ast.expr,
    imported_symbols: dict[str, str | ast.expr | None],
) -> str | None:
    if isinstance(expression, ast.Name):
        if expression.id in imported_symbols:
            resolved = imported_symbols[expression.id]
        elif expression.id in {"setattr", "getattr"}:
            # Bare builtin references are canonicalised only when the lexical
            # scope has not shadowed the builtin name.
            return f"builtins.{expression.id}"
        else:
            resolved = expression.id
        if isinstance(resolved, ast.expr):
            return _resolve_imported_symbol(resolved, imported_symbols)
        return resolved
    if isinstance(expression, (ast.Attribute, ast.Subscript)):
        root_name = _storage_root_name(expression)
        if (
            root_name is not None
            and imported_symbols.get(root_name) == _INDETERMINATE_TRUSTED_ALIAS
        ):
            return _INDETERMINATE_TRUSTED_ALIAS
    if isinstance(expression, ast.Attribute):
        parent = _resolve_imported_symbol(expression.value, imported_symbols)
        return f"{parent}.{expression.attr}" if parent else None
    if isinstance(expression, ast.IfExp):
        # Either branch may execute. Treat a trusted target in either branch
        # as a boundary violation even when the condition is not knowable.
        candidates = {
            _resolve_imported_symbol(expression.body, imported_symbols),
            _resolve_imported_symbol(expression.orelse, imported_symbols),
        }
        for trusted_target in (
            "cephas_logisticsos.tenancy.trusted_context.TrustedTenantContextAdapter",
            "cephas_logisticsos.composition.build_tenant_context_adapter",
        ):
            if trusted_target in candidates:
                return trusted_target
        return next(iter(candidates)) if len(candidates) == 1 else None
    if isinstance(expression, ast.Subscript):
        container = _resolve_container_expression(expression.value, imported_symbols)
        index = _literal_container_index(expression.slice)
        if container is not None and index is not None:
            elements = container.elts
            if -len(elements) <= index < len(elements):
                return _resolve_imported_symbol(elements[index], imported_symbols)
    return None


def _is_builtin_operation(
    expression: ast.expr,
    builtin_name: str,
    imported_symbols: dict[str, str | ast.expr | None],
) -> bool:
    """Resolve direct, imported, module-qualified and assigned builtin aliases."""
    return _resolve_imported_symbol(expression, imported_symbols) == f"builtins.{builtin_name}"


def _contains_trusted_boundary_reference(
    expression: ast.expr,
    imported_symbols: dict[str, str | ast.expr | None],
) -> bool:
    """Find known trusted-boundary references inside unsupported expressions.

    This narrow taint check does not reject arbitrary indirect calls. It marks
    expressions only when their syntax or a retained container alias refers to
    a known trusted constructor, factory, trusted module, or tainted alias.
    """
    trusted_targets = {
        "cephas_logisticsos.tenancy.trusted_context.TrustedTenantContextAdapter",
        "cephas_logisticsos.composition.build_tenant_context_adapter",
        "cephas_logisticsos.tenancy",
        "cephas_logisticsos.tenancy.trusted_context",
        "cephas_logisticsos.composition",
        _INDETERMINATE_TRUSTED_ALIAS,
    }
    inspected_aliases: set[str] = set()

    def visit(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            mapped = imported_symbols.get(node.id)
            if mapped == _INDETERMINATE_TRUSTED_ALIAS:
                return True
            if isinstance(mapped, ast.expr) and node.id not in inspected_aliases:
                inspected_aliases.add(node.id)
                if visit(mapped):
                    return True

        if isinstance(node, ast.expr):
            resolved = _resolve_imported_symbol(node, imported_symbols)
            if resolved in trusted_targets:
                return True

        return any(visit(child) for child in ast.iter_child_nodes(node))

    return visit(expression)


def _bind_assignment_aliases(
    target: ast.expr,
    value: ast.expr,
    imported_symbols: dict[str, str | ast.expr | None],
) -> bool:
    """Bind names introduced by simple, statically resolvable assignments."""
    if isinstance(value, ast.Name):
        mapped_value = imported_symbols.get(value.id)
        if isinstance(mapped_value, ast.expr):
            value = mapped_value
    if isinstance(target, ast.Name):
        resolved = _resolve_imported_symbol(value, imported_symbols)
        if resolved is not None:
            if imported_symbols.get(target.id) == resolved:
                return False
            imported_symbols[target.id] = resolved
            return True
        container_value = _resolve_container_expression(value, imported_symbols)
        if container_value is not None:
            if imported_symbols.get(target.id) is container_value:
                return False
            imported_symbols[target.id] = container_value
            return True
        if _contains_trusted_boundary_reference(value, imported_symbols):
            if imported_symbols.get(target.id) == _INDETERMINATE_TRUSTED_ALIAS:
                return False
            imported_symbols[target.id] = _INDETERMINATE_TRUSTED_ALIAS
            return True
        return False
    if isinstance(target, (ast.Attribute, ast.Subscript)) and _contains_trusted_boundary_reference(
        value, imported_symbols
    ):
        # Attribute and subscript mutation changes storage reachable through the
        # root object. Conservatively taint that root so later reads, including
        # dynamic-key reads and chained attribute access, remain indeterminate.
        root_name = _storage_root_name(target)
        if (
            root_name is not None
            and imported_symbols.get(root_name) != _INDETERMINATE_TRUSTED_ALIAS
        ):
            imported_symbols[root_name] = _INDETERMINATE_TRUSTED_ALIAS
            return True
        return False
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
        starred = [index for index, item in enumerate(target.elts) if isinstance(item, ast.Starred)]
        if len(starred) > 1:
            return False
        if not starred:
            if len(target.elts) != len(value.elts):
                return False
            pairs = zip(target.elts, value.elts, strict=True)
        else:
            star_index = starred[0]
            suffix_count = len(target.elts) - star_index - 1
            if len(value.elts) < star_index + suffix_count:
                return False
            middle_end = len(value.elts) - suffix_count
            pairs = iter(
                [
                    *zip(target.elts[:star_index], value.elts[:star_index], strict=True),
                    (
                        target.elts[star_index].value,
                        ast.List(elts=value.elts[star_index:middle_end], ctx=ast.Load()),
                    ),
                    *zip(
                        target.elts[star_index + 1 :],
                        value.elts[middle_end:],
                        strict=True,
                    ),
                ]
            )
        changed = False
        for target_item, value_item in pairs:
            changed = _bind_assignment_aliases(target_item, value_item, imported_symbols) or changed
        return changed
    return False


def _trusted_boundary_call_violations(
    source: str,
    *,
    module_name: str,
) -> list[tuple[int, str]]:
    """Resolve trusted constructor/factory calls without leaking aliases across scopes."""
    tree = ast.parse(source)
    violations: list[tuple[int, str]] = []
    package_name = module_name.rpartition(".")[0]
    constructor = "cephas_logisticsos.tenancy.trusted_context.TrustedTenantContextAdapter"
    factory = "cephas_logisticsos.composition.build_tenant_context_adapter"
    trusted_modules = {
        "cephas_logisticsos.tenancy",
        "cephas_logisticsos.tenancy.trusted_context",
        "cephas_logisticsos.composition",
    }

    def direct_scope_nodes(statements: list[ast.stmt]) -> list[ast.AST]:
        """Walk this scope but do not descend into a nested lexical scope."""
        collected: list[ast.AST] = []
        stack: list[ast.AST] = list(reversed(statements))
        while stack:
            node = stack.pop()
            collected.append(node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Decorators, defaults and annotations execute (or are evaluated
                # under the active annotation mode) in the enclosing scope.
                # Scan these expressions here, but leave the function body for
                # its own lexical environment below.
                definition_expressions: list[ast.AST] = [
                    *node.decorator_list,
                    *node.args.defaults,
                    *(item for item in node.args.kw_defaults if item is not None),
                ]
                for argument in [
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                ]:
                    if argument.annotation is not None:
                        definition_expressions.append(argument.annotation)
                if node.args.vararg is not None and node.args.vararg.annotation is not None:
                    definition_expressions.append(node.args.vararg.annotation)
                if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
                    definition_expressions.append(node.args.kwarg.annotation)
                if node.returns is not None:
                    definition_expressions.append(node.returns)
                # Generic type-parameter bounds/defaults are also definition-time
                # expressions on Python versions that expose type_params.
                definition_expressions.extend(getattr(node, "type_params", ()))
                stack.extend(reversed(definition_expressions))
                continue
            if isinstance(node, ast.ClassDef):
                # Class decorators, bases and keyword values execute in the
                # enclosing scope; the class body has its own namespace.
                definition_expressions = [
                    *node.decorator_list,
                    *node.bases,
                    *(keyword.value for keyword in node.keywords),
                ]
                definition_expressions.extend(getattr(node, "type_params", ()))
                stack.extend(reversed(definition_expressions))
                continue
            if isinstance(node, ast.Lambda):
                # Lambda defaults execute in the enclosing scope; its body is a
                # separate function scope and is intentionally not traversed here.
                definition_expressions = [
                    *node.args.defaults,
                    *(item for item in node.args.kw_defaults if item is not None),
                ]
                stack.extend(reversed(definition_expressions))
                continue
            stack.extend(reversed(list(ast.iter_child_nodes(node))))
        return collected

    def imported_name(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> tuple[str, str]:
        if isinstance(node, ast.Import):
            local_name = alias.asname or alias.name.split(".")[0]
            qualified = alias.name if alias.asname else local_name
            return local_name, qualified
        if node.level:
            package_parts = package_name.split(".") if package_name else []
            keep = max(0, len(package_parts) - node.level + 1)
            prefix = ".".join(package_parts[:keep])
            if node.module:
                prefix = ".".join(part for part in (prefix, node.module) if part)
        else:
            prefix = node.module or ""
        local_name = alias.asname or alias.name
        qualified = ".".join(part for part in (prefix, alias.name) if part)
        return local_name, qualified

    def target_names(target: ast.expr) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names: set[str] = set()
            for item in target.elts:
                names.update(target_names(item.value if isinstance(item, ast.Starred) else item))
            return names
        if isinstance(target, ast.Starred):
            return target_names(target.value)
        return set()

    def analyze_scope(
        statements: list[ast.stmt],
        inherited_symbols: dict[str, str | ast.expr | None],
        *,
        scope_kind: str,
        parameters: set[str] | None = None,
    ) -> None:
        nodes = direct_scope_nodes(statements)
        symbols = dict(inherited_symbols)
        local_names: set[str] = set()
        assignments: list[tuple[ast.expr, ast.expr]] = []
        nested_scopes: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []

        # Function parameters are local bindings too and shadow inherited names.
        if parameters:
            local_names.update(parameters)

        # Predeclare names bound in this lexical scope. This models Python's
        # function-local shadowing even when the assignment appears after a call.
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                local_names.add(node.name)
                nested_scopes.append(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    local_names.update(target_names(target))
                if node.value is not None:
                    assignments.extend((target, node.value) for target in targets)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                local_names.update(target_names(node.target))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        local_names.update(target_names(item.optional_vars))
            elif isinstance(node, ast.ExceptHandler) and node.name:
                local_names.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local_name, _ = imported_name(node, alias)
                    local_names.add(local_name)

        for name in local_names:
            symbols[name] = None

        # Imports are resolved only in this scope; a local import never rewrites
        # a binding in the enclosing module or function.
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local_name, qualified = imported_name(node, alias)
                    if alias.name == "*" and isinstance(node, ast.ImportFrom):
                        if qualified.rpartition(".")[0] in trusted_modules:
                            violations.append((node.lineno, f"star-import:{qualified}"))
                        continue
                    symbols[local_name] = qualified

        # Resolve aliases to a fixed point, but only in this scope's private map.
        for _ in range(len(local_names) + 1):
            changed = False
            for target, value in assignments:
                changed = _bind_assignment_aliases(target, value, symbols) or changed
            if not changed:
                break

        # Track object aliases independently from trusted-symbol aliases.  This is
        # deliberately a bounded, scope-local may-alias model: direct name aliases
        # share a storage identity, and any trusted write taints every known alias.
        storage_parent = {name: name for name in local_names}

        def storage_root(name: str) -> str:
            parent = storage_parent.setdefault(name, name)
            if parent != name:
                storage_parent[name] = storage_root(parent)
            return storage_parent[name]

        def join_storage(left: str, right: str) -> None:
            left_root = storage_root(left)
            right_root = storage_root(right)
            if left_root != right_root:
                storage_parent[right_root] = left_root

        # Only the final statically visible binding determines a name's
        # current storage identity. This avoids permanently merging an alias
        # with an object after that name has been reassigned.
        final_name_bindings: dict[str, ast.expr] = {}
        for target, value in assignments:
            if isinstance(target, ast.Name):
                final_name_bindings[target.id] = value
        for target_name, value in final_name_bindings.items():
            if isinstance(value, ast.Name):
                # A name resolving to a trusted callable is a callable alias,
                # not an alias to the registry/object that stores callables.
                if _resolve_imported_symbol(value, symbols) is None:
                    join_storage(target_name, value.id)
            elif isinstance(value, (ast.Attribute, ast.Subscript)):
                source_root = _storage_root_name(value)
                if source_root is not None and _resolve_imported_symbol(value, symbols) is None:
                    join_storage(target_name, source_root)

        def taint_storage(name: str) -> None:
            root = storage_root(name)
            for alias_name in tuple(storage_parent):
                if storage_root(alias_name) == root:
                    symbols[alias_name] = _INDETERMINATE_TRUSTED_ALIAS

        # Attribute/subscript writes taint the shared object, not just the
        # variable spelling used at the write site. Unsupported roots fail closed.
        for target, value in assignments:
            if not isinstance(target, (ast.Attribute, ast.Subscript)):
                continue
            if not _contains_trusted_boundary_reference(value, symbols):
                continue
            root_name = _storage_root_name(target)
            if root_name is None:
                violations.append((target.lineno, "indeterminate-trusted-storage-write"))
            else:
                taint_storage(root_name)

        # Recognise common mutating APIs when their arguments carry a trusted
        # reference. Module-qualified and imported operator functions are modelled
        # by their resolved symbol, not by the spelling of the call expression.
        mutating_methods = {"update", "append", "extend", "__setitem__", "setdefault"}
        for call in (node for node in nodes if isinstance(node, ast.Call)):
            arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
            trusted_arguments = any(
                _contains_trusted_boundary_reference(argument, symbols) for argument in arguments
            )
            if not trusted_arguments:
                continue

            resolved_call = _resolve_imported_symbol(call.func, symbols)
            receiver: ast.expr | None = None
            is_storage_mutation = False

            if isinstance(call.func, ast.Attribute) and call.func.attr in mutating_methods:
                receiver = call.func.value
                is_storage_mutation = True
            elif _is_builtin_operation(call.func, "setattr", symbols) and len(call.args) >= 3:
                receiver = call.args[0]
                is_storage_mutation = True
            elif resolved_call == "operator.setitem" and len(call.args) >= 3:
                # operator.setitem(container, key, value) mutates arg[0].
                receiver = call.args[0]
                is_storage_mutation = True

            if is_storage_mutation and receiver is not None:
                receiver_root = _storage_root_name(receiver)
                if receiver_root is None:
                    violations.append((call.lineno, "indeterminate-trusted-storage-mutation"))
                else:
                    taint_storage(receiver_root)

        # Revisit name assignments after storage taint is known. A callable
        # retrieved through an alias to a mutated registry must itself become
        # indeterminate before call sites are classified.
        for _ in range(len(local_names) + 1):
            changed = False
            for target, value in assignments:
                if not isinstance(target, ast.Name):
                    continue
                source_root = (
                    value.id
                    if isinstance(value, ast.Name)
                    else _storage_root_name(value)
                    if isinstance(value, (ast.Attribute, ast.Subscript))
                    else (
                        _storage_root_name(value.args[0])
                        if isinstance(value, ast.Call)
                        and value.args
                        and (
                            _is_builtin_operation(value.func, "getattr", symbols)
                            or _resolve_imported_symbol(value.func, symbols) == "operator.getitem"
                        )
                        else None
                    )
                )
                if (
                    source_root is not None
                    and symbols.get(source_root) == _INDETERMINATE_TRUSTED_ALIAS
                    and symbols.get(target.id) != _INDETERMINATE_TRUSTED_ALIAS
                ):
                    symbols[target.id] = _INDETERMINATE_TRUSTED_ALIAS
                    changed = True
            if not changed:
                break

        # Calls in this scope are evaluated against this scope's own map.
        # A retrieval expression can itself be the callable; inspect its storage
        # argument, not only node.func's apparent callable name.
        def tainted_retrieval_receiver(expression: ast.expr) -> bool:
            if not isinstance(expression, ast.Call) or not expression.args:
                return False
            is_getattr = _is_builtin_operation(expression.func, "getattr", symbols)
            is_operator_getitem = (
                _resolve_imported_symbol(expression.func, symbols) == "operator.getitem"
            )
            if not (is_getattr or is_operator_getitem):
                return False
            receiver_root = _storage_root_name(expression.args[0])
            return (
                receiver_root is None or symbols.get(receiver_root) == _INDETERMINATE_TRUSTED_ALIAS
            )

        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            resolved = _resolve_imported_symbol(node.func, symbols)
            if resolved == constructor:
                violations.append((node.lineno, "TrustedTenantContextAdapter"))
            elif resolved == factory:
                violations.append((node.lineno, "build_tenant_context_adapter"))
            elif (
                resolved == _INDETERMINATE_TRUSTED_ALIAS
                or (resolved is None and _contains_trusted_boundary_reference(node.func, symbols))
                or tainted_retrieval_receiver(node.func)
            ):
                violations.append((node.lineno, "indeterminate-trusted-boundary-call"))

        # A method defined in a class does not close over the class namespace.
        # Function scopes do inherit enclosing function/module bindings.
        child_parent = inherited_symbols if scope_kind == "class" else symbols
        for nested in nested_scopes:
            if isinstance(nested, ast.ClassDef):
                analyze_scope(nested.body, symbols, scope_kind="class")
            else:
                arguments = nested.args
                parameter_names = {
                    argument.arg
                    for argument in [
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                    ]
                }
                if arguments.vararg is not None:
                    parameter_names.add(arguments.vararg.arg)
                if arguments.kwarg is not None:
                    parameter_names.add(arguments.kwarg.arg)
                analyze_scope(
                    nested.body,
                    child_parent if scope_kind == "class" else symbols,
                    scope_kind="function",
                    parameters=parameter_names,
                )

    analyze_scope(tree.body, {}, scope_kind="module")
    return violations

def _production_source_boundary_violations(
    source_by_module: dict[str, str],
) -> list[str]:
    """Apply the production-source composition rule to module source text."""
    violations: list[str] = []
    for module_name, source in source_by_module.items():
        for line, target in _trusted_boundary_call_violations(
            source,
            module_name=module_name,
        ):
            if module_name != "cephas_logisticsos.composition":
                violations.append(f"{module_name}:{line}:{target}")
    return violations


def scan_source_tree(source_root: Path) -> list[str]:
    """Scan every Python source module and return policy violations."""
    if not source_root.is_dir():
        raise FileNotFoundError(f"source directory does not exist: {source_root}")
    source_by_module: dict[str, str] = {}
    for path in sorted(source_root.rglob("*.py")):
        module_name = ".".join(path.relative_to(source_root).with_suffix("").parts)
        source_by_module[module_name] = path.read_text(encoding="utf-8")
    return _production_source_boundary_violations(source_by_module)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("src"))
    args = parser.parse_args(argv)
    try:
        violations = scan_source_tree(args.source)
    except (OSError, UnicodeError) as error:
        parser.error(str(error))
    if violations:
        print("Trusted tenant-boundary policy violations:")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print(f"Trusted tenant-boundary scan passed: {args.source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
