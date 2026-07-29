// Created: 2026-04-16 by Constructor Tech
//! `OData` filter field definitions for GTS type resources.

use toolkit_odata_macros::ODataFilterable;

/// Type filterable fields schema.
///
/// This struct defines which fields can be used in `OData` `$filter` queries
/// for GTS type resources. The field names match the wire format.
#[derive(ODataFilterable)]
pub struct TypeQuery {
    #[odata(filter(kind = "String"))]
    pub code: String,
}

/// Type alias for the generated filter field enum.
pub use TypeQueryFilterField as TypeFilterField;
