use rayon::prelude::*;

pub(crate) fn map_collect<T, O, E, F>(items: Vec<T>, map: F) -> Result<Vec<O>, E>
where
    T: Send,
    O: Send,
    E: Send,
    F: Fn(T) -> Result<O, E> + Sync + Send,
{
    items.into_par_iter().map(map).collect()
}

pub(crate) fn map_slice_collect<'a, T, O, E, F>(items: &'a [T], map: F) -> Result<Vec<O>, E>
where
    T: Sync + 'a,
    O: Send,
    E: Send,
    F: Fn(&'a T) -> Result<O, E> + Sync + Send,
{
    items.par_iter().map(map).collect()
}
