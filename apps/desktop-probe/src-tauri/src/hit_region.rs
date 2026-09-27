use serde::{Deserialize, Serialize};

const ORB_CSS_INSET: f64 = 8.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HitRegionStatus {
    Pending,
    CircularApplied,
    RectangularFallbackUnsupported,
    RectangularFallbackApplyFailed,
    FailedClosed,
    Rectangular,
    Opaque,
    Unknown,
}

impl HitRegionStatus {
    pub(crate) fn is_native_circle(self) -> bool {
        matches!(self, Self::CircularApplied)
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::CircularApplied => "circular-applied",
            Self::RectangularFallbackUnsupported => "rectangular-fallback-unsupported",
            Self::RectangularFallbackApplyFailed => "rectangular-fallback-apply-failed",
            Self::FailedClosed => "failed-closed",
            Self::Rectangular => "rectangular",
            Self::Opaque => "opaque",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowGeometryEvent {
    Created,
    Resized,
    ScaleFactorChanged,
    Moved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HitRegionController {
    mode: HitRegionMode,
    platform: HitRegionPlatform,
    status: HitRegionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitRegionMode {
    TransparentOrb,
    Rectangular,
    Opaque,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitRegionPlatform {
    Windows,
    Unsupported,
}

impl HitRegionController {
    pub(crate) fn new(mode: &str, platform: &str) -> Self {
        let mode = match mode {
            "transparent-orb" => HitRegionMode::TransparentOrb,
            "transparent-window-with-rectangular-hit-region" => HitRegionMode::Rectangular,
            "opaque-frameless-fallback" => HitRegionMode::Opaque,
            _ => HitRegionMode::Unknown,
        };
        let platform = if platform == "windows" {
            HitRegionPlatform::Windows
        } else {
            HitRegionPlatform::Unsupported
        };
        let status = match (mode, platform) {
            (HitRegionMode::TransparentOrb, HitRegionPlatform::Windows) => HitRegionStatus::Pending,
            (HitRegionMode::TransparentOrb, HitRegionPlatform::Unsupported) => {
                HitRegionStatus::RectangularFallbackUnsupported
            }
            (HitRegionMode::Rectangular, _) => HitRegionStatus::Rectangular,
            (HitRegionMode::Opaque, _) => HitRegionStatus::Opaque,
            (HitRegionMode::Unknown, _) => HitRegionStatus::Unknown,
        };

        Self {
            mode,
            platform,
            status,
        }
    }

    pub(crate) fn status(self) -> HitRegionStatus {
        self.status
    }

    pub(crate) fn can_pass(self) -> bool {
        match self.mode {
            HitRegionMode::TransparentOrb => self.status.is_native_circle(),
            HitRegionMode::Rectangular => self.status == HitRegionStatus::Rectangular,
            HitRegionMode::Opaque => self.status == HitRegionStatus::Opaque,
            HitRegionMode::Unknown => false,
        }
    }

    pub(crate) fn on_window_geometry(
        &mut self,
        event: WindowGeometryEvent,
        width: u32,
        height: u32,
        scale_factor: f64,
        mut apply_circle: impl FnMut((i32, i32, i32, i32)) -> bool,
        mut clear_to_rectangle: impl FnMut() -> bool,
    ) {
        if self.mode != HitRegionMode::TransparentOrb
            || self.platform != HitRegionPlatform::Windows
            || !matches!(
                event,
                WindowGeometryEvent::Created
                    | WindowGeometryEvent::Resized
                    | WindowGeometryEvent::ScaleFactorChanged
            )
        {
            return;
        }

        let bounds = calculate_circle_region_bounds(width, height, scale_factor);
        let applied = bounds.is_some_and(&mut apply_circle);
        if applied {
            self.status = HitRegionStatus::CircularApplied;
        } else if clear_to_rectangle() {
            self.status = HitRegionStatus::RectangularFallbackApplyFailed;
        } else {
            self.status = HitRegionStatus::FailedClosed;
        }
    }
}

fn calculate_circle_region_bounds(
    width: u32,
    height: u32,
    scale_factor: f64,
) -> Option<(i32, i32, i32, i32)> {
    if width == 0 || height == 0 || !scale_factor.is_finite() || scale_factor <= 0.0 {
        return None;
    }
    let inset = (ORB_CSS_INSET * scale_factor).round() as u32;
    if width <= inset.saturating_mul(2) || height <= inset.saturating_mul(2) {
        return None;
    }
    Some((
        inset as i32,
        inset as i32,
        (width - inset) as i32,
        (height - inset) as i32,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        HitRegionController, HitRegionStatus, WindowGeometryEvent, calculate_circle_region_bounds,
    };

    #[test]
    fn windows_circle_region_matches_css_inset_at_96_dpi() {
        assert_eq!(
            calculate_circle_region_bounds(360, 360, 1.0),
            Some((8, 8, 352, 352))
        );
    }

    #[test]
    fn windows_circle_region_scales_css_inset_for_dpi_changes() {
        assert_eq!(
            calculate_circle_region_bounds(540, 540, 1.5),
            Some((12, 12, 528, 528))
        );
    }

    #[test]
    fn circle_region_reapplies_after_creation_resize_and_dpi_change_only() {
        let mut controller = HitRegionController::new("transparent-orb", "windows");
        let mut applied = Vec::new();
        let mut clear_calls = 0;

        for (event, width, height, scale) in [
            (WindowGeometryEvent::Created, 360, 360, 1.0),
            (WindowGeometryEvent::Resized, 540, 540, 1.5),
            (WindowGeometryEvent::ScaleFactorChanged, 540, 540, 1.5),
            (WindowGeometryEvent::Moved, 540, 540, 1.5),
        ] {
            controller.on_window_geometry(
                event,
                width,
                height,
                scale,
                |bounds| {
                    applied.push(bounds);
                    true
                },
                || {
                    clear_calls += 1;
                    true
                },
            );
        }

        assert_eq!(
            applied,
            [(8, 8, 352, 352), (12, 12, 528, 528), (12, 12, 528, 528)]
        );
        assert_eq!(clear_calls, 0);
        assert_eq!(controller.status(), HitRegionStatus::CircularApplied);
    }

    #[test]
    fn unsupported_platform_uses_rectangular_fallback_and_cannot_pass_orb_mode() {
        for platform in ["macos", "x11", "wayland"] {
            let mut controller = HitRegionController::new("transparent-orb", platform);
            let mut native_calls = 0;
            controller.on_window_geometry(
                WindowGeometryEvent::Created,
                360,
                360,
                1.0,
                |_| {
                    native_calls += 1;
                    true
                },
                || true,
            );

            assert_eq!(native_calls, 0, "{platform} must not claim a native circle");
            assert_eq!(
                controller.status(),
                HitRegionStatus::RectangularFallbackUnsupported
            );
            assert!(!controller.can_pass());
        }
    }

    #[test]
    fn failed_region_update_clears_to_rectangular_fallback() {
        let mut controller = HitRegionController::new("transparent-orb", "windows");
        controller.on_window_geometry(
            WindowGeometryEvent::Created,
            360,
            360,
            1.0,
            |_| false,
            || true,
        );

        assert_eq!(
            controller.status(),
            HitRegionStatus::RectangularFallbackApplyFailed
        );
        assert!(!controller.can_pass());
    }

    #[test]
    fn failed_region_update_and_failed_clear_are_fail_closed() {
        let mut controller = HitRegionController::new("transparent-orb", "windows");
        controller.on_window_geometry(
            WindowGeometryEvent::ScaleFactorChanged,
            540,
            540,
            1.5,
            |_| false,
            || false,
        );

        assert_eq!(controller.status(), HitRegionStatus::FailedClosed);
        assert!(!controller.can_pass());
    }

    #[test]
    fn explicit_fallback_build_modes_do_not_request_circular_regions() {
        let rectangular =
            HitRegionController::new("transparent-window-with-rectangular-hit-region", "windows");
        let opaque = HitRegionController::new("opaque-frameless-fallback", "windows");

        assert_eq!(rectangular.status(), HitRegionStatus::Rectangular);
        assert_eq!(opaque.status(), HitRegionStatus::Opaque);
        assert!(rectangular.can_pass());
        assert!(opaque.can_pass());
    }
}
