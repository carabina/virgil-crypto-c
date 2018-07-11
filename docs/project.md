Define project as set of interfaces, implementators and modules.s

Summary of language
===================

This summary shows the hierarchy of elements you can use, with the
required and optional attributes for each element.  The XML entity and
attribute names are case-sensitive and we use only lower-case names.

    <project name brief prefix namespace path inc_path inc_private_path src_path work_path>
       <interface name/>
       <implementor name/>
       <module name/>
       <feature name [prefix]>
          <source [name] [type]/>
          <require [feature]>
             <source .../>
             <alternative [feature]>
                <source .../>
             </alternative>
          </require>
       </feature>
    </project>

Detailed specifications
=======================

All child entities are optional and can occur zero or more times without
any specific limits unless otherwise specified.  The same tag may occur
at different levels with different meanings, and in such cases will be
detailed more than once here.

The 'project' item
------------------

Define project as set of interfaces, implementators and modules.

    <project
        name = "..."
        brief = "..."
        prefix = "..."
        namespace = "..."
        path = "..."
        inc_path = "..."
        inc_private_path = "..."
        src_path = "..."
        work_path = "..."
        >
        <interface>
        <implementor>
        <module>
        <feature>
    </project>

The project item can have these attributes:

name:
    Project name. The name attribute is required.

brief:
    Project brief description. The brief attribute is required.

prefix:
    Prefix for C names within project. The prefix attribute is required.

namespace:
    Project namespace. This attribute is used to for wrappers that support
    namesapces. The namespace attribute is required.

path:
    Path to the project root directory. The path attribute is required.

inc_path:
    Path to the directory with public headers. The inc_path attribute is
    required.

inc_private_path:
    Path to the directory with private headers. The inc_private_path
    attribute is required.

src_path:
    Path to the directory with source files. The src_path attribute is
    required.

work_path:
    Path to the directory, that is used to hold temporary files. The
    work_path attribute is required.


The 'interface' item
--------------------

Define supported interface.

    <interface
        name = "..."
        />

The interface item has this single attribute:

name:
    Interface name. The name attribute is required.


The 'implementor' item
----------------------

Define supported implementor.

    <implementor
        name = "..."
        />

The implementor item has this single attribute:

name:
    Implementor name. The name attribute is required.


The 'module' item
-----------------

Define supported module.

    <module
        name = "..."
        />

The module item has this single attribute:

name:
    Module name. The name attribute is required.


The 'feature' item
------------------

Define provided feature.

    <feature
        name = "..."
      [ prefix = "..." ]
        >
        <source>, required
        <require>
    </feature>

The feature item can have these attributes:

name:
    Feature name. The name attribute is required.

prefix:
    Feature prefix. This attribute is derived from parent's attribute
    'prefix'. The prefix attribute is optional.


The 'source' item
-----------------

Provide attributes that defines the source of featur(e). This entity is
inherited.

    <source
      [ name = "..." ]
      [ type = "project | library" ]
        />

The source item can have these attributes:

name:
    Source name The name attribute is optional.

type:
    The source type of the feature(s). The type attribute is optional. It can
    take one of the following values:

Value: Meaning:
project: Feture(s) are provided by inner project.
library: Feture(s) are provided by external library.


The 'require' item
------------------

Define required feature. Note, attribute 'feature' or inner entity
'alternative' must be defined. If attribute name is not defined, then at
least 2 'alternative' entities are expected.

    <require
      [ feature = "..." ]
        >
        <source>, required
        <alternative>
    </require>

The require item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.


The 'alternative' item
----------------------

Define alternative features that can be used, and in fact replace each
other.

    <alternative
      [ feature = "..." ]
        >
        <source>, required
    </alternative>

The alternative item has this single attribute:

feature:
    Required feature name. The feature attribute is optional.
