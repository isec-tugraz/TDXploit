use anyhow::{Context, Result};
use glob::glob;

///get filename for data and metadta file from common prefix
pub fn prefix_to_filename_tuple(s: &str) -> (String, String) {
    let data_path = format!("{}_data.csv", s);
    let metadata_path = format!("{}_metadata.csv", s);
    (data_path, metadata_path)
}

///list of all data metadata file pairs in the given folder. not recursive
pub fn get_file_list(folder_path: String) -> Result<Vec<(String, String)>> {
    let data_file_pattern = "*_data.csv";

    let glob_string = format!("{}{}", folder_path, data_file_pattern);

    let mut result = Vec::new();
    println!("glob pattern {}", glob_string);
    for entry in glob(&glob_string).context(format!("glob for {} failed", &glob_string))? {
        let entry = entry.context("failed to read directory entry")?;
        let data_file = entry
            .to_str()
            .expect("failed to convert to string")
            .to_string();
        let metadata_file = data_file.trim_end_matches("_data.csv").to_string() + "_metadata.csv";
        println!("({},{})", data_file, metadata_file);
        result.push((data_file, metadata_file));
    }

    Ok(result)
}
