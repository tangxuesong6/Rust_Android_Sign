use criterion::{Criterion, criterion_group, criterion_main};

use sign_cms_lib::get_sign;

// cargo bench -p sign_cms_lib

fn bench_get_sign() {
    let dir = "../files/app-release.apk";
    let _rst = get_sign(dir.to_string()).unwrap();
    // match rst {
    //     Ok(s) => println!("ok: {}", s),
    //     Err(e) => println!("err: {}", e)
    // }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("get_sign", |b| b.iter(|| bench_get_sign()));
}

criterion_group!(benches, criterion_benchmark);

criterion_main!(benches);