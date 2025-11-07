//! Module registry for managing analysis modules

use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::module::AnalysisModule;
use crate::domain::value_objects::ModuleType;

/// Registry for analysis modules
pub struct ModuleRegistry {
    modules: HashMap<ModuleType, Arc<dyn AnalysisModule>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Register a module
    pub fn register(&mut self, module: Arc<dyn AnalysisModule>) {
        self.modules.insert(module.module_type(), module);
    }

    /// Get a module by type
    pub fn get_module(&self, module_type: &ModuleType) -> Option<Arc<dyn AnalysisModule>> {
        self.modules.get(module_type).cloned()
    }

    /// Get all registered module types
    pub fn registered_modules(&self) -> Vec<ModuleType> {
        self.modules.keys().cloned().collect()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
