//! Source classification for coverage; deliberately outside the product workspace.
use std::{
    io::{self, BufRead},
    path::Path,
};
use syn::{spanned::Spanned, visit::Visit, Attribute, Meta};

// Whether a cfg expression can be true in a production build. Non-test cfg
// predicates are unknown here: platform-only code must not disappear from the
// inventory simply because this machine cannot execute it.
fn possible_without_test(meta: &Meta) -> (bool, bool) {
    match meta {
        Meta::Path(path) if path.is_ident("test") => (false, true),
        Meta::List(list)
            if list.path.is_ident("all")
                || list.path.is_ident("any")
                || list.path.is_ident("not") =>
        {
            use syn::{parse::Parser, punctuated::Punctuated, Token};
            let args = Punctuated::<Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .unwrap();
            let values: Vec<_> = args.iter().map(possible_without_test).collect();
            if list.path.is_ident("all") {
                (values.iter().all(|v| v.0), values.iter().any(|v| v.1))
            } else if list.path.is_ident("any") {
                (values.iter().any(|v| v.0), values.iter().all(|v| v.1))
            } else {
                assert_eq!(values.len(), 1);
                (values[0].1, values[0].0)
            }
        }
        _ => (true, true),
    }
}
fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && !possible_without_test(&attr.parse_args::<Meta>().unwrap()).0)
    })
}
#[derive(Default)]
struct Inventory {
    excluded: Vec<[usize; 2]>,
    declarations: Vec<serde_json::Value>,
    in_test: bool,
    modules: Vec<serde_json::Value>,
}
impl Inventory {
    fn exclude(&mut self, attrs: &[Attribute], span: proc_macro2::Span) -> bool {
        if self.in_test || test_only(attrs) {
            self.excluded.push([span.start().line, span.end().line]);
            true
        } else {
            false
        }
    }
}
impl<'ast> Visit<'ast> for Inventory {
    fn visit_file(&mut self, node: &'ast syn::File) {
        let previous = self.in_test;
        self.in_test = self.exclude(&node.attrs, node.span());
        syn::visit::visit_file(self, node);
        self.in_test = previous;
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.content.is_none() {
            let explicit_path = node
                .attrs
                .iter()
                .find(|a| a.path().is_ident("path"))
                .and_then(|a| {
                    if let Meta::NameValue(v) = &a.meta {
                        if let syn::Expr::Lit(lit) = &v.value {
                            if let syn::Lit::Str(s) = &lit.lit {
                                return Some(s.value());
                            }
                        }
                    }
                    None
                });
            self.modules.push(serde_json::json!({"name":node.ident.to_string(),"path":explicit_path,"test_only":self.in_test || test_only(&node.attrs)}));
        }
        let previous = self.in_test;
        self.in_test = self.exclude(&node.attrs, node.span());
        syn::visit::visit_item_mod(self, node);
        self.in_test = previous;
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.in_test;
        self.in_test = self.exclude(&node.attrs, node.span());
        syn::visit::visit_item_impl(self, node);
        self.in_test = previous;
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let excluded = self.exclude(&node.attrs, node.span());
        self.declarations.push(serde_json::json!({"name":node.sig.ident.to_string(), "line":node.sig.span().start().line, "end":node.span().end().line,"test_only":excluded}));
        let previous = self.in_test;
        self.in_test = excluded;
        syn::visit::visit_item_fn(self, node);
        self.in_test = previous;
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let excluded = self.exclude(&node.attrs, node.span());
        self.declarations.push(serde_json::json!({"name":node.sig.ident.to_string(), "line":node.sig.span().start().line, "end":node.span().end().line,"test_only":excluded}));
        let previous = self.in_test;
        self.in_test = excluded;
        syn::visit::visit_impl_item_fn(self, node);
        self.in_test = previous;
    }
}
fn main() {
    let mode = std::env::args().nth(1).expect("source or demangle");
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if mode == "demangle" {
            println!("{:#}", rustc_demangle::demangle(&line));
        } else if mode == "source" {
            let source = std::fs::read_to_string(Path::new(&line)).unwrap();
            let syntax = syn::parse_file(&source).unwrap();
            let mut inventory = Inventory::default();
            inventory.visit_file(&syntax);
            println!(
                "{}",
                serde_json::json!({"path":line,"test_ranges":inventory.excluded,"declarations":inventory.declarations,"modules":inventory.modules})
            );
        } else {
            panic!("unknown mode");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_test_only_from_platform_production_code() {
        for (source, expected) in [
            ("test", false),
            ("all(test, unix)", false),
            ("any(test, target_arch = \"wasm32\")", true),
            ("not(test)", true),
            ("all(unix, not(test))", true),
            ("not(any(test, unix))", true),
        ] {
            assert_eq!(
                possible_without_test(&syn::parse_str::<Meta>(source).unwrap()).0,
                expected,
                "{source}"
            );
        }
    }
    #[test]
    fn excludes_helpers_and_nested_functions_but_preserves_wasm_shared_code() {
        let syntax = syn::parse_file(
            r#"
            #[cfg(test)] fn helper() { fn nested() {} }
            #[cfg(any(test, target_arch = "wasm32"))] fn shared() {}
            #[cfg(test)] mod support;
            struct Example;
            #[cfg(test)] impl Example { fn helper_method() {} }
        "#,
        )
        .unwrap();
        let mut inventory = Inventory::default();
        inventory.visit_file(&syntax);
        assert_eq!(
            inventory
                .declarations
                .iter()
                .map(|d| d["test_only"].as_bool().unwrap())
                .collect::<Vec<_>>(),
            vec![true, true, false, true]
        );
        assert_eq!(inventory.modules[0]["test_only"], true);
    }
}
