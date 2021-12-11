use metrics::counter;
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub struct CianRenameField<'a> {
    pub old_field: &'a str,
    pub new_field: &'a str,
}

impl<'a> InternalEvent for CianRenameField<'a> {
    fn emit_logs(&self) {
        warn!(
            message = "Field overwritten.",
            old_field = %self.old_field,
            new_field = %self.new_field,
            internal_log_rate_secs = 30
        );
    }

    fn emit_metrics(&self) {
        let metric = format!("rename__{}__{}", &self.old_field, &self.new_field);
        counter!(metric, 1);
    }

}

#[derive(Debug)]
pub struct CianDeleteLegacyField<'a> {
    pub field: &'a str,
}

impl<'a> InternalEvent for CianDeleteLegacyField<'a> {
    fn emit_logs(&self) {
        warn!(
            message = "Legacy field deleted.",
            field = %self.field,
            internal_log_rate_secs = 30
        );
    }

    fn emit_metrics(&self) {
        let metric = format!("delete_legacy__{}", &self.field);
        counter!(metric, 1);
    }
}