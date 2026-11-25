//! Output writing utilities

use anyhow::Result;
use rdnsx_core::asn::IpAsnRecord;
use rdnsx_core::DnsRecord;
use std::io::{self, BufWriter, Write};

pub struct OutputWriter {
    writer: BufWriter<Box<dyn Write>>,
    json_output: bool,
    silent: bool,
}

impl OutputWriter {
    pub fn new(output_file: Option<String>, json_output: bool, silent: bool) -> Result<Self> {
        let raw_writer: Box<dyn Write> = if let Some(file) = output_file {
            Box::new(std::fs::File::create(file)?)
        } else {
            Box::new(io::stdout())
        };

        Ok(Self {
            writer: BufWriter::new(raw_writer),
            json_output,
            silent,
        })
    }

    pub fn is_json(&self) -> bool {
        self.json_output
    }

    #[allow(dead_code)]
    pub fn is_silent(&self) -> bool {
        self.silent
    }

    pub fn write_record(&mut self, record: &DnsRecord, resp_only: bool) -> Result<()> {
        // Results are always written; --silent only hides the banner and
        // progress messages on stderr, so `rdnsx --silent ... | grep` works.
        if resp_only {
            if record.is_negative() {
                writeln!(self.writer, "{}", record.response_code)?;
            } else {
                writeln!(self.writer, "{}", record.value)?;
            }
        } else if self.json_output {
            let json = serde_json::to_string(record)?;
            writeln!(self.writer, "{}", json)?;
        } else {
            writeln!(self.writer, "{}", record)?;
        }

        Ok(())
    }

    /// Write a record, with its origin AS when one is given
    pub fn write_record_with_asn(
        &mut self,
        record: &DnsRecord,
        resp_only: bool,
        asn: Option<&IpAsnRecord>,
    ) -> Result<()> {
        let Some(asn) = asn else {
            return self.write_record(record, resp_only);
        };
        let summary = format!(
            "AS{} {}{}{}",
            asn.asn,
            asn.prefix,
            asn.country
                .as_deref()
                .map(|c| format!(" {}", c))
                .unwrap_or_default(),
            asn.as_name
                .as_deref()
                .map(|n| format!(" {}", n))
                .unwrap_or_default()
        );
        if resp_only {
            writeln!(self.writer, "{} [{}]", record.value, summary)?;
        } else if self.json_output {
            let mut json = serde_json::to_value(record)?;
            if let Some(obj) = json.as_object_mut() {
                obj.insert("asn".to_string(), serde_json::to_value(asn)?);
            }
            writeln!(self.writer, "{}", json)?;
        } else {
            writeln!(self.writer, "{} [{}]", record, summary)?;
        }
        Ok(())
    }

    pub fn write_json<T: serde::Serialize>(&mut self, value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        writeln!(self.writer, "{}", line)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
