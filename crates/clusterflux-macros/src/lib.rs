use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};
use sha2::{Digest as _, Sha256};
use syn::{
    parse::Parser, parse_macro_input, Data, DeriveInput, Expr, FnArg, ItemFn, Lit, LitByteStr,
    Meta, ReturnType, Token, Type,
};

#[proc_macro_derive(TaskArg)]
pub fn derive_task_arg(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    match &input.data {
        Data::Struct(_) | Data::Enum(_) => {}
        Data::Union(union) => {
            return syn::Error::new_spanned(
                union.union_token,
                "TaskArg cannot be derived for unions",
            )
            .into_compile_error()
            .into();
        }
    };
    quote! {
        impl #impl_generics ::clusterflux::__private::CollectTaskHandles
            for #name #type_generics #where_clause
        {}

        impl #impl_generics ::clusterflux::TaskArg for #name #type_generics #where_clause {
            fn task_arg_kind(&self) -> ::clusterflux::TaskArgKind {
                ::clusterflux::TaskArgKind::Structured
            }

            fn task_boundary_value(
                &self,
            ) -> ::std::result::Result<
                ::clusterflux::core::TaskBoundaryValue,
                ::clusterflux::TaskArgError,
            > {
                ::clusterflux::__private::structured_task_boundary(self)
            }
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);
    if !function.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &function.sig,
            "#[clusterflux::main] requires a function with no arguments",
        )
        .into_compile_error()
        .into();
    }
    let function_name = function.sig.ident.to_string();
    let (entrypoint_name, _, explicit_default) = descriptor_options(
        attr,
        function_name
            .strip_suffix("_main")
            .unwrap_or(&function_name),
    );
    let descriptor = format_ident!(
        "__CLUSTERFLUX_ENTRYPOINT_{}",
        function_name.to_ascii_uppercase()
    );
    let argument_schema = argument_schema(&function);
    let result_schema = result_schema(&function);
    let stable_id = stable_digest(
        "clusterflux-entrypoint-id:v1",
        &[
            &entrypoint_name,
            &function_name,
            &argument_schema,
            &result_schema,
        ],
    );
    let export_name = format!(
        "clusterflux_entry_v1_{}",
        stable_id.trim_start_matches("sha256:")
    );
    let export_wrapper = format_ident!(
        "__clusterflux_entry_export_{}",
        function_name.to_ascii_lowercase()
    );
    let export_invocation = invocation_helper(&function, true, quote! { #entrypoint_name });
    let probe_symbol = format!(
        "clusterflux.probe.{}",
        stable_id.trim_start_matches("sha256:")
    );
    let manifest = serde_json::json!({
        "kind": "entrypoint",
        "name": entrypoint_name,
        "function": function_name,
        "export": export_name,
        "stable_id": stable_id,
        "argument_schema": argument_schema,
        "result_schema": result_schema,
        "abi_version": 1,
        "probe_symbol": probe_symbol,
        "default": explicit_default,
    });
    let manifest = manifest_record(manifest);
    let manifest_static = format_ident!(
        "__CLUSTERFLUX_ENTRYPOINT_MANIFEST_{}",
        function_name.to_ascii_uppercase()
    );

    quote! {
        #function

        #[doc(hidden)]
        pub const #descriptor: ::clusterflux::EntrypointDescriptor = ::clusterflux::EntrypointDescriptor {
            name: #entrypoint_name,
            function: #function_name,
            export: #export_name,
            stable_id: #stable_id,
            argument_schema: #argument_schema,
            result_schema: #result_schema,
            abi_version: 1,
            bundle_manifest_entry: true,
        };

        #[doc(hidden)]
        #[used]
        #[cfg_attr(target_arch = "wasm32", unsafe(link_section = "clusterflux.entrypoints"))]
        pub static #manifest_static: [u8; #manifest.len()] = *#manifest;

        #[doc(hidden)]
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #export_wrapper(input_pointer: u32, input_length: u32) -> u64 {
            ::clusterflux::debug::probe_at(#probe_symbol, file!(), line!())
                .expect("Clusterflux entrypoint debug probe host call failed");
            #export_invocation
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn task(attr: TokenStream, item: TokenStream) -> TokenStream {
    let function = parse_macro_input!(item as ItemFn);
    if function.sig.inputs.len() > 1 {
        return syn::Error::new_spanned(
            &function.sig,
            "#[clusterflux::task] requires a function with zero or one owned argument",
        )
        .into_compile_error()
        .into();
    }
    let function_name = function.sig.ident.to_string();
    let (task_name, required_capabilities, _) = descriptor_options(attr, &function_name);
    let descriptor = format_ident!("__CLUSTERFLUX_TASK_{}", function_name.to_ascii_uppercase());
    let argument_schema = argument_schema(&function);
    let result_schema = result_schema(&function);
    let capability_schema = required_capabilities.join(",");
    let stable_id = stable_digest(
        "clusterflux-task-id:v1",
        &[&task_name, &function_name, &argument_schema, &result_schema],
    );
    let restart_compatibility_hash = stable_digest(
        "clusterflux-task-restart:v1",
        &[
            &task_name,
            &argument_schema,
            &result_schema,
            &capability_schema,
            "abi:1",
        ],
    );
    let export_name = format!(
        "clusterflux_task_v1_{}",
        stable_id.trim_start_matches("sha256:")
    );
    let export_wrapper = format_ident!(
        "__clusterflux_task_export_{}",
        function_name.to_ascii_lowercase()
    );
    let export_invocation = invocation_helper(&function, false, quote! { #task_name });
    let probe_symbol = format!(
        "clusterflux.probe.{}",
        stable_id.trim_start_matches("sha256:")
    );
    let manifest = serde_json::json!({
        "kind": "task",
        "name": task_name,
        "function": function_name,
        "export": export_name,
        "stable_id": stable_id,
        "argument_schema": argument_schema,
        "result_schema": result_schema,
        "required_capabilities": required_capabilities,
        "restart_compatibility_hash": restart_compatibility_hash,
        "abi_version": 1,
        "probe_symbol": probe_symbol,
    });
    let manifest = manifest_record(manifest);
    let manifest_static = format_ident!(
        "__CLUSTERFLUX_TASK_MANIFEST_{}",
        function_name.to_ascii_uppercase()
    );

    quote! {
        #function

        #[doc(hidden)]
        pub const #descriptor: ::clusterflux::TaskDescriptor = ::clusterflux::TaskDescriptor {
            name: #task_name,
            function: #function_name,
            export: #export_name,
            stable_id: #stable_id,
            argument_schema: #argument_schema,
            result_schema: #result_schema,
            required_capabilities: &[#(#required_capabilities),*],
            restart_compatibility_hash: #restart_compatibility_hash,
            abi_version: 1,
            source_file: file!(),
            source_line: line!(),
            probe_symbol: #probe_symbol,
            bundle_manifest_entry: true,
            remotely_startable: true,
        };

        #[doc(hidden)]
        #[used]
        #[cfg_attr(target_arch = "wasm32", unsafe(link_section = "clusterflux.tasks"))]
        pub static #manifest_static: [u8; #manifest.len()] = *#manifest;

        #[doc(hidden)]
        #[cfg(target_arch = "wasm32")]
        #[unsafe(export_name = #export_name)]
        pub extern "C" fn #export_wrapper(input_pointer: u32, input_length: u32) -> u64 {
            ::clusterflux::debug::probe_at(#probe_symbol, file!(), line!())
                .expect("Clusterflux task debug probe host call failed");
            #export_invocation
        }
    }
    .into()
}

fn invocation_helper(
    function: &ItemFn,
    is_entrypoint: bool,
    expected_definition: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let function_ident = &function.sig.ident;
    let asynchronous = function.sig.asyncness.is_some();
    let result_return = returns_result(&function.sig.output);
    let helper = match (asynchronous, result_return, function.sig.inputs.len()) {
        (false, false, 0) => format_ident!("invoke_task0_v1"),
        (false, true, 0) => format_ident!("invoke_task0_result_v1"),
        (true, false, 0) => format_ident!("invoke_task0_async_v1"),
        (true, true, 0) => format_ident!("invoke_task0_async_result_v1"),
        (false, false, 1) => format_ident!("invoke_task1_v1"),
        (false, true, 1) => format_ident!("invoke_task1_result_v1"),
        (true, false, 1) => format_ident!("invoke_task1_async_v1"),
        (true, true, 1) => format_ident!("invoke_task1_async_result_v1"),
        _ => unreachable!("attribute input count was validated"),
    };
    match function.sig.inputs.first() {
        None => quote! {
            ::clusterflux::__private::#helper(
                #expected_definition,
                input_pointer,
                input_length,
                || #function_ident(),
            )
        },
        Some(FnArg::Typed(argument)) if !is_entrypoint => {
            let argument_type = &argument.ty;
            quote! {
                ::clusterflux::__private::#helper(
                    #expected_definition,
                    input_pointer,
                    input_length,
                    |argument: #argument_type| #function_ident(argument),
                )
            }
        }
        Some(FnArg::Typed(_)) => unreachable!("entrypoint arguments were rejected"),
        Some(FnArg::Receiver(receiver)) => syn::Error::new_spanned(
            receiver,
            "#[clusterflux::task] cannot be applied to a method",
        )
        .into_compile_error(),
    }
}

fn returns_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, output) = output else {
        return false;
    };
    let Type::Path(path) = output.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Result")
}

fn descriptor_options(attr: TokenStream, default: &str) -> (String, Vec<String>, bool) {
    if attr.is_empty() {
        return (default.to_owned(), Vec::new(), false);
    }

    let parser = syn::punctuated::Punctuated::<Meta, Token![,]>::parse_terminated;
    let Ok(args) = parser.parse(attr) else {
        return (default.to_owned(), Vec::new(), false);
    };

    let mut name = default.to_owned();
    let mut capabilities = Vec::new();
    let mut explicit_default = false;
    for meta in args {
        let Meta::NameValue(name_value) = meta else {
            continue;
        };
        if let Expr::Lit(expr) = name_value.value {
            match expr.lit {
                Lit::Str(value) if name_value.path.is_ident("name") => name = value.value(),
                Lit::Str(value) if name_value.path.is_ident("capabilities") => {
                    capabilities = value
                        .value()
                        .split(',')
                        .map(str::trim)
                        .filter(|capability| !capability.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                Lit::Bool(value) if name_value.path.is_ident("default") => {
                    explicit_default = value.value;
                }
                _ => {}
            }
        }
    }

    (name, capabilities, explicit_default)
}

fn argument_schema(function: &ItemFn) -> String {
    function
        .sig
        .inputs
        .iter()
        .map(ToTokens::to_token_stream)
        .map(|tokens| tokens.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn result_schema(function: &ItemFn) -> String {
    match &function.sig.output {
        ReturnType::Default => "()".to_owned(),
        ReturnType::Type(_, result) => result.to_token_stream().to_string(),
    }
}

fn stable_digest(domain: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn manifest_record(value: serde_json::Value) -> LitByteStr {
    let mut record = serde_json::to_vec(&value).expect("descriptor manifest serializes");
    record.push(b'\n');
    LitByteStr::new(&record, proc_macro2::Span::call_site())
}
