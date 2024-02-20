extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, ItemStatic, Type, TypePath};

fn type_checking(type_path: &TypePath) -> bool {
    let type_name = type_path.path.segments.last().unwrap().ident.to_string();

    match type_name.as_str() {
        "u8" => (),
        "i8" => (),
        "i16" => (),
        "u16" => (),
        "i32" => (),
        "u32" => (),
        "i64" => (),
        "u64" => (),
        _ => return false,
    }

    true
}

#[proc_macro_attribute]
pub fn entry_link(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut ast = parse_macro_input!(item as ItemStatic);
    let link_para: String = attr.into_iter().map(|x| x.to_string()).collect();
    let link_section = parse_quote!(#[link_section = #link_para]);
    let used = parse_quote!(#[used]);

    ast.attrs.push(link_section);
    ast.attrs.push(used);
    TokenStream::from(quote! { #ast })
}

fn field_type_check(ty: Type) -> Result<(), TokenStream> {
    if let Type::Path(type_path) = ty {
        if !type_checking(&type_path) {
            return Err(
                syn::Error::new_spanned(&type_path, "All fields must be numeric type")
                    .to_compile_error()
                    .into(),
            );
        }
    } else if let Type::Array(type_array) = ty {
        // convert [T; N] to T
        return field_type_check(*type_array.elem);
    } else if let Type::Reference(type_ref) = ty {
        // convert &'a T to T
        return field_type_check(*type_ref.elem);
    } else {
        // TODO: add more detailed type hints
        return Err(
            syn::Error::new_spanned(&ty, "All fields must be validate type")
                .to_compile_error()
                .into(),
        );
    }
    Ok(())
}

#[proc_macro_derive(FieldTransmute)]
pub fn ensure_numberic(input: TokenStream) -> TokenStream {
    let input_copy = input.clone();
    let ast: DeriveInput = parse_macro_input!(input as DeriveInput);
    let struct_name = ast.ident;

    match ast.data {
        Data::Struct(s) => match s.fields {
            Fields::Named(fields) => {
                for field in fields.named {
                    if let Err(err) = field_type_check(field.ty) {
                        return err;
                    }
                }
            }
            _ => (),
        },
        _ => (),
    }

    let ast: DeriveInput = parse_macro_input!(input_copy as DeriveInput);
    let mut fields_token = vec![];

    if let Data::Struct(s) = ast.data {
        for field in s.fields {
            let field_type = &field.ty;
            // get field ident
            let _ = field.ident.as_ref().unwrap();

            let token = quote!( direct_packet_access_ok::<#field_type>(); );
            fields_token.push(token);
        }
    }

    // You can still derive other traits, or just generate an empty implementation
    let gen = quote! {
        impl #struct_name {
            #[inline(always)]
            pub(crate) fn new(data: &mut [u8]) -> &mut #struct_name{
             #(#fields_token)*
             unsafe { convert_slice_to_struct_mut::<#struct_name>(data) }
            }
        }
    };
    gen.into()
}
