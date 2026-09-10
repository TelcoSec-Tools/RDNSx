//! Output writing utilities

use anyhow::Result;
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
        if self.silent {
            return Ok(());
        }

        if resp_only {
            writeln!(self.writer, "{}", record.value)?;
        } else if self.json_output {
            let json = serde_json::to_string(record)?;
            writeln!(self.writer, "{}", json)?;
        } else {
            writeln!(self.writer, "{}", record)?;
        }

        Ok(())
    }

    pub fn write_json<T: serde::Serialize>(&mut self, value: &T) -> Result<()> {
        if self.silent {
            return Ok(());
        }
        let json = serde_json::to_string_pretty(value)?;
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        if self.silent {
            return Ok(());
        }
        writeln!(self.writer, "{}", line)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
