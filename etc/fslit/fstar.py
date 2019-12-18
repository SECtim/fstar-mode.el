import re

from pygments.lexer import RegexLexer, DelegatingLexer, bygroups, include, \
    using, this, default, words
from pygments.token import Punctuation, \
    Text, Comment, Operator, Keyword, Name, String, Number, Literal, Other
from pygments.util import get_choice_opt, iteritems
from pygments import unistring as uni

from pygments.lexers.html import XmlLexer

__all__ = ['FStarLexer']

class FStarLexer(RegexLexer):
    """
    For the `F* language <https://fsharp.org/>`_ (version 3.0).

    .. versionadded:: 1.5
    """

    name = 'F*'
    aliases = ['fstar', 'f*']
    filenames = ['*.fst', '*.fsti']
    mimetypes = ['text/x-fstar']

    keywords = [
        'abstract', 'as', 'assert', 'base', 'begin', 'class', 'default',
        'delegate', 'do!', 'do', 'done', 'downcast', 'downto', 'elif', 'else',
        'end', 'exception', 'extern', 'false', 'finally', 'for', 'function',
        'fun', 'global', 'if', 'inherit', 'inline', 'interface', 'internal',
        'in', 'lazy', 'let!', 'let', 'match', 'member', 'module', 'mutable',
        'namespace', 'new', 'null', 'of', 'open', 'override', 'private', 'public',
        'rec', 'return!', 'return', 'select', 'static', 'struct', 'then', 'to',
        'true', 'try', 'type', 'upcast', 'use!', 'use', 'val', 'void', 'when',
        'while', 'with', 'yield!', 'yield',
    ]
    # Reserved words; cannot hurt to color them as keywords too.
    keywords += [
        'atomic', 'break', 'checked', 'component', 'const', 'constraint',
        'constructor', 'continue', 'eager', 'event', 'external', 'fixed',
        'functor', 'include', 'method', 'mixin', 'object', 'parallel',
        'process', 'protected', 'pure', 'sealed', 'tailcall', 'trait',
        'virtual', 'volatile',
    ]
    keyopts = [
        '!=', '#', '&&', '&', r'\(', r'\)', r'\*', r'\+', ',', r'-\.',
        '->', '-', r'\.\.', r'\.', '::', ':=', ':>', ':', ';;', ';', '<-',
        r'<\]', '<', r'>\]', '>', r'\?\?', r'\?', r'\[<', r'\[\|', r'\[', r'\]',
        '_', '`', r'\{', r'\|\]', r'\|', r'\}', '~', '<@@', '<@', '=', '@>', '@@>',
    ]

    operators = r'[!$%&*+\./:<=>?@^|~-]'
    word_operators = ['and', 'or', 'not']
    prefix_syms = r'[!?~]'
    infix_syms = r'[=<>@^|&+\*/$%-]'
    primitives = [
        'sbyte', 'byte', 'char', 'nativeint', 'unativeint', 'float32', 'single',
        'float', 'double', 'int8', 'uint8', 'int16', 'uint16', 'int32',
        'uint32', 'int64', 'uint64', 'decimal', 'unit', 'bool', 'string',
        'list', 'exn', 'obj', 'enum',
    ]

    # See http://msdn.microsoft.com/en-us/library/dd233181.aspx and/or
    # http://fsharp.org/about/files/spec.pdf for reference.  Good luck.

    tokens = {
        'escape-sequence': [
            (r'\\[\\"\'ntbrafv]', String.Escape),
            (r'\\[0-9]{3}', String.Escape),
            (r'\\u[0-9a-fA-F]{4}', String.Escape),
            (r'\\U[0-9a-fA-F]{8}', String.Escape),
        ],
        'root': [
            (r'\s+', Text),
            (r'\(\)|\[\]', Name.Builtin.Pseudo),
            (r'\b(?<!\.)([A-Z][\w\']*)(?=\s*\.)',
             Name.Namespace, 'dotted'),
            (r'\b([A-Z][\w\']*)', Name),
            (r'///.*?\n', String.Doc),
            (r'//.*?\n', Comment.Single),
            (r'\(\*(?!\))', Comment, 'comment'),

            (r'@"', String, 'lstring'),
            (r'"""', String, 'tqs'),
            (r'"', String, 'string'),

            (r'\b(open|module)(\s+)([\w.]+)',
             bygroups(Keyword, Text, Name.Namespace)),
            (r'\b(let!?)(\s+)(\w+)',
             bygroups(Keyword, Text, Name.Variable)),
            (r'\b(type)(\s+)(\w+)',
             bygroups(Keyword, Text, Name.Class)),
            (r'\b(member|override)(\s+)(\w+)(\.)(\w+)',
             bygroups(Keyword, Text, Name, Punctuation, Name.Function)),
            (r'\b(%s)\b' % '|'.join(keywords), Keyword),
            (r'``([^`\n\r\t]|`[^`\n\r\t])+``', Name),
            (r'(%s)' % '|'.join(keyopts), Operator),
            (r'(%s|%s)?%s' % (infix_syms, prefix_syms, operators), Operator),
            (r'\b(%s)\b' % '|'.join(word_operators), Operator.Word),
            (r'\b(%s)\b' % '|'.join(primitives), Keyword.Type),
            (r'#[ \t]*(if|endif|else|line|nowarn|light|\d+)\b.*?\n',
             Comment.Preproc),

            (r"[^\W\d][\w']*", Name),

            (r'\d[\d_]*[uU]?[yslLnQRZINGmM]?', Number.Integer),
            (r'0[xX][\da-fA-F][\da-fA-F_]*[uU]?[yslLn]?[fF]?', Number.Hex),
            (r'0[oO][0-7][0-7_]*[uU]?[yslLn]?', Number.Oct),
            (r'0[bB][01][01_]*[uU]?[yslLn]?', Number.Bin),
            (r'-?\d[\d_]*(.[\d_]*)?([eE][+\-]?\d[\d_]*)[fFmM]?',
             Number.Float),

            (r"'(?:(\\[\\\"'ntbr ])|(\\[0-9]{3})|(\\x[0-9a-fA-F]{2}))'B?",
             String.Char),
            (r"'.'", String.Char),
            (r"'", Keyword),  # a stray quote is another syntax element

            (r'@?"', String.Double, 'string'),

            (r'[~?][a-z][\w\']*:', Name.Variable),
        ],
        'dotted': [
            (r'\s+', Text),
            (r'\.', Punctuation),
            (r'[A-Z][\w\']*(?=\s*\.)', Name.Namespace),
            (r'[A-Z][\w\']*', Name, '#pop'),
            (r'[a-z_][\w\']*', Name, '#pop'),
            # e.g. dictionary index access
            default('#pop'),
        ],
        'comment': [
            (r'[^(*)@"]+', Comment),
            (r'\(\*', Comment, '#push'),
            (r'\*\)', Comment, '#pop'),
            # comments cannot be closed within strings in comments
            (r'@"', String, 'lstring'),
            (r'"""', String, 'tqs'),
            (r'"', String, 'string'),
            (r'[(*)@]', Comment),
        ],
        'string': [
            (r'[^\\"]+', String),
            include('escape-sequence'),
            (r'\\\n', String),
            (r'\n', String),  # newlines are allowed in any string
            (r'"B?', String, '#pop'),
        ],
        'lstring': [
            (r'[^"]+', String),
            (r'\n', String),
            (r'""', String),
            (r'"B?', String, '#pop'),
        ],
        'tqs': [
            (r'[^"]+', String),
            (r'\n', String),
            (r'"""B?', String, '#pop'),
            (r'"', String),
        ],
    }
