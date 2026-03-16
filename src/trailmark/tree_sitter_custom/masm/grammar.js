/**
 * @file Miden Assembly grammar for tree-sitter
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

module.exports = grammar({
  name: "masm",

  extras: ($) => [/[\t\r\f\v \n]+/, $.comment],

  supertypes: ($) => [$.op, $.form],

  word: ($) => $.identifier,

  rules: {
    source_file: ($) =>
      seq(optional($.moduledoc), repeat($.form)),

    form: ($) =>
      choice($.import, $.reexport, $.constant, $.procedure, $.entrypoint, $.type_decl, $.adv_map_decl),

    // ── Comments & docs ────────────────────────────────────────────

    moduledoc: ($) => prec(2, repeat1($.doc_comment_line)),
    doc_comment: ($) => prec(1, repeat1($.doc_comment_line)),
    doc_comment_line: (_) => token(seq("#!", /[^\n]*/)),
    comment: (_) => token(seq("#", /[^\n]*/)),

    // ── Top-level forms ────────────────────────────────────────────

    import: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        "use", field("path", $.path),
      ),

    reexport: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        "pub", "use", field("path", $.path),
      ),

    constant: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        "const",
        field("name", $.const_ident),
        "=",
        field("value", $.const_expr),
      ),

    entrypoint: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        "begin",
        field("body", $.block),
        "end",
      ),

    procedure: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        field("annotations", repeat($.annotation)),
        field("visibility", optional("pub")),
        "proc",
        field("name", $._ident),
        field("params", optional($.param_list)),
        field("return_type", optional($.return_type)),
        field("body", $.block),
        "end",
      ),

    type_decl: ($) =>
      seq(
        field("docs", optional($.doc_comment)),
        optional("pub"),
        "type",
        field("name", $.type_ident),
        "=",
        field("value", $.type_value),
      ),

    type_value: ($) =>
      choice($.struct_type, $.type_ident),

    struct_type: ($) =>
      seq(
        "struct",
        "{",
        optional(seq($.struct_field, repeat(seq(",", $.struct_field)))),
        optional(","),
        "}",
      ),

    adv_map_decl: ($) =>
      seq(
        "adv_map",
        field("name", $.const_ident),
        "=",
        "[",
        optional(seq($._integer, repeat(seq(",", $._integer)))),
        optional(","),
        "]",
      ),

    struct_field: ($) =>
      seq(field("name", $.identifier), ":", field("type", $.type_ident)),

    param_list: ($) =>
      seq(
        "(",
        optional(seq($.param, repeat(seq(",", $.param)))),
        ")",
      ),

    param: ($) =>
      seq(
        field("name", $._ident),
        ":",
        field("type", $.type_expr),
      ),

    return_type: ($) => seq("->", $.type_expr),

    type_expr: ($) =>
      choice(
        $.tuple_type,
        $.type_ident,
      ),

    tuple_type: ($) =>
      seq("(", $._tuple_element, repeat1(seq(",", $._tuple_element)), ")"),

    _tuple_element: ($) =>
      seq($.type_ident, optional(seq(":", $.type_ident))),

    type_ident: (_) => /[a-zA-Z_][a-zA-Z0-9_]*/,

    // ── Annotations ────────────────────────────────────────────────

    annotation: ($) =>
      seq(
        "@",
        field("name", $.identifier),
        field("value", optional($.annotation_args)),
      ),

    annotation_args: ($) =>
      seq(token.immediate("("), $._annotation_value, ")"),

    _annotation_value: ($) =>
      choice($.decimal, $.identifier, $.string),

    // ── Block & ops ────────────────────────────────────────────────

    block: ($) => repeat1($.op),

    op: ($) =>
      choice(
        $.assert_op,
        $.debug,
        $.push,
        $.emit,
        $.trace,
        $.op_with_optional_immediate,
        $.op_with_stack_index,
        $.op_with_local_index,
        $.adv_injector,
        $.opcode,
        $.if,
        $.while,
        $.repeat,
        $.invoke,
      ),

    // ── Nullary opcodes ────────────────────────────────────────────

    opcode: (_) =>
      choice(
        "nop",
        "breakpoint",
        // Arithmetic (strictly nullary — no immediate variant)
        "inv", "neg",
        // Boolean
        "not", "and", "or", "xor",
        // Comparison (strictly nullary)
        "eqw",
        // Stack manipulation
        "drop", "dropw", "padw", "swapdw",
        "cdrop", "cdropw", "cswap", "cswapw",
        // u32 operations (strictly nullary)
        "u32split", "u32test", "u32testw", "u32cast",
        "u32overflowing_add3",
        "u32wrapping_add3", "u32wrapping_madd",
        "u32widening_add", "u32widening_add3", "u32widening_madd",
        "u32clo", "u32clz", "u32cto", "u32ctz",
        "u32popcnt",
        // Hashing
        "hash", "hperm", "hmerge",
        // Extension field
        "ext2add", "ext2mul", "ext2div", "ext2inv", "ext2sub", "ext2neg",
        // Merkle tree
        "mtree_get", "mtree_set", "mtree_merge",
        // Memory/advice
        "mem_stream", "adv_loadw", "adv_pipe",
        // Misc
        "sdepth", "pow2", "is_odd", "ilog2",
        "fri_ext2fold4", "horner_eval_base", "horner_eval_ext",
        "reversew", "eval_circuit", "log_precompile",
        "arithmetic_circuit_eval",
        "caller", "clk", "dyncall", "dynexec",
        "crypto_stream",
      ),

    // ── Opcodes with optional immediate (.N) ───────────────────────

    op_with_optional_immediate: ($) =>
      seq(
        field(
          "op",
          choice(
            "add", "sub", "mul", "div",
            "eq", "neq", "lt", "gt", "gte", "lte",
            "exp",
            "u32overflowing_add", "u32overflowing_mul", "u32overflowing_sub",
            "u32wrapping_add", "u32wrapping_sub", "u32wrapping_mul",
            "u32widening_mul",
            "u32and", "u32or", "u32xor", "u32not",
            "u32div", "u32divmod", "u32mod",
            "u32gt", "u32gte", "u32lt", "u32lte", "u32max", "u32min",
            "u32shl", "u32shr", "u32rotl", "u32rotr",
            "mem_load", "mem_loadw", "mem_store", "mem_storew",
            "mem_loadw_be", "mem_storew_be", "mem_loadw_le", "mem_storew_le",
          ),
        ),
        field("imm", optional($._dot_value)),
      ),

    op_with_stack_index: ($) =>
      seq(
        field(
          "op",
          choice(
            "dup", "dupw", "swap", "swapw",
            "movup", "movupw", "movdn", "movdnw",
            "adv_push",
          ),
        ),
        field("index", optional($._dot_decimal)),
      ),

    op_with_local_index: ($) =>
      seq(
        field(
          "op",
          choice(
            "locaddr",
            "loc_load", "loc_loadw", "loc_store", "loc_storew",
            "loc_loadw_be", "loc_storew_be", "loc_loadw_le", "loc_storew_le",
          ),
        ),
        field("local", optional($._dot_decimal)),
      ),

    // ── Assert (with optional .err=string) ─────────────────────────

    assert_op: ($) =>
      seq(
        field(
          "op",
          choice(
            "assert", "assertz", "assert_eq", "assert_eqw",
            "u32assert", "u32assert2", "u32assertw",
            "mtree_verify",
          ),
        ),
        field("err", optional($._err_clause)),
      ),

    _err_clause: ($) =>
      seq(
        token.immediate("."),
        token.immediate("err"),
        token.immediate("="),
        choice($.string, $.const_ident),
      ),

    // ── Push ───────────────────────────────────────────────────────

    push: ($) => seq("push", repeat1($._dot_push_value)),

    _dot_push_value: ($) =>
      seq(token.immediate("."), $._push_value),

    _push_value: ($) =>
      choice(
        $.word_literal,
        token.immediate(/0x[a-fA-F0-9]+(_[a-fA-F0-9]+)*/),
        token.immediate(/(0|[1-9][0-9]*)/),
        $.const_ident,
      ),

    word_literal: ($) =>
      seq(
        token.immediate("["),
        $._integer,
        repeat(seq(",", $._integer)),
        "]",
      ),

    // ── Emit / Trace ──────────────────────────────────────────────

    emit: ($) =>
      seq("emit", token.immediate("."), field("event", $.const_ident)),

    trace: ($) =>
      seq("trace", token.immediate("."), field("index", $.decimal)),

    // ── Debug ─────────────────────────────────────────────────────

    debug: ($) =>
      seq(
        "debug",
        token.immediate("."),
        choice(
          token.immediate("stack"),
          token.immediate("mem"),
          token.immediate("local"),
          token.immediate("adv_stack"),
        ),
        repeat($._dot_decimal),
      ),

    // ── Adv injectors ─────────────────────────────────────────────

    adv_injector: (_) =>
      choice(
        "adv.insert_hdword",
        "adv.insert_hdword_d",
        "adv.insert_hperm",
        "adv.insert_mem",
        "adv.push_ext2intt",
        "adv.push_mapval",
        "adv.push_mapvaln",
        "adv.push_mtnode",
        "adv.push_smtpeek",
        "adv.push_u64div",
        "adv.push_falcon_div",
        "adv_map",
      ),

    // ── Control flow ──────────────────────────────────────────────

    if: ($) =>
      seq(
        "if.true",
        field("then_body", $.block),
        optional(seq("else", field("else_body", $.block))),
        "end",
      ),

    while: ($) => seq("while.true", field("body", $.block), "end"),

    repeat: ($) =>
      seq(
        "repeat",
        token.immediate("."),
        field("count", $.decimal),
        field("body", $.block),
        "end",
      ),

    // ── Invocations ───────────────────────────────────────────────

    invoke: ($) =>
      seq(
        field("kind", choice("exec", "call", "syscall", "procref")),
        token.immediate("."),
        field("path", $.path),
      ),

    // ── Paths ─────────────────────────────────────────────────────

    path: ($) => choice($.absolute_path, $.relative_path),

    absolute_path: ($) =>
      repeat1(seq(token.immediate("::"), $._ident)),

    relative_path: ($) =>
      seq($._ident, repeat(seq(token.immediate("::"), $._ident))),

    // ── Constant expressions ──────────────────────────────────────

    const_expr: ($) => choice($.const_binop, $._const_term),

    const_binop: ($) =>
      choice(
        prec.left(3, seq(field("lhs", $.const_expr), "*", field("rhs", $.const_expr))),
        prec.left(2, seq(field("lhs", $.const_expr), "/", field("rhs", $.const_expr))),
        prec.left(2, seq(field("lhs", $.const_expr), "//", field("rhs", $.const_expr))),
        prec.left(1, seq(field("lhs", $.const_expr), "+", field("rhs", $.const_expr))),
        prec.left(1, seq(field("lhs", $.const_expr), "-", field("rhs", $.const_expr))),
      ),

    _const_term: ($) =>
      choice($.const_group, $.event_call, $.number, $.string, $.const_ident),

    const_group: ($) => seq("(", field("expr", $.const_expr), ")"),

    event_call: ($) =>
      seq("event", "(", $.string, ")"),

    // ── Shared tokens ─────────────────────────────────────────────

    _dot_decimal: ($) =>
      seq(token.immediate("."), token.immediate(/(0|[1-9][0-9]*)/)),

    _dot_value: ($) =>
      seq(
        token.immediate("."),
        choice(
          token.immediate(/(0|[1-9][0-9]*)/),
          token.immediate(/0x[a-fA-F0-9]+/),
          token.immediate("u32"),
          $.const_ident,
        ),
      ),

    _ident: ($) => choice(alias($.string, $.quoted_ident), $.identifier),
    identifier: (_) => /[a-z_$][a-zA-Z0-9_$]*/,
    const_ident: (_) => /[A-Z_][A-Z0-9_$]*/,

    string: ($) => seq('"', optional($.string_content), '"'),
    string_content: (_) => token.immediate(/[^"\n]+/),

    number: ($) => choice($.decimal, $.hex),
    _integer: ($) => choice($.decimal, $.hex),
    decimal: (_) => /(0|[1-9](_?[0-9])*)/,
    hex: (_) => /0x[a-fA-F0-9]+(_[a-fA-F0-9]+)*/,
  },
});
