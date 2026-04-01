use serde::{Deserialize, Serialize};

use crate::model::common::SortDirection;
use crate::model::list_query::NoInclude;

pub const KB: usize = 1 << 10;
pub const MB: usize = KB << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundedB64Image<const MAX: usize>(pub(crate) String);

#[derive(Clone, Debug)]
pub struct ListQueryDTO<SortColumn, Filter, Include = NoInclude> {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    pub filter: Filter,
    pub include: Option<Vec<Include>>,
}
