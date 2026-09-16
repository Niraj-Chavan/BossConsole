package ai.rever.boss.components.home

import ai.rever.boss.components.overlays.HoverTooltipBox
import ai.rever.boss.plugin.ui.BossTheme
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.ButtonDefaults
import androidx.compose.material.Icon
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Home
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** Window navigation, kept outside the list of closable tabs. */
@Composable
internal fun HomeNavigationButton(
    selected: Boolean,
    compact: Boolean = false,
    onClick: () -> Unit,
) {
    HoverTooltipBox(text = "Go Home in this pane") {
        TextButton(
            onClick = onClick,
            modifier =
                (if (compact) Modifier.size(36.dp) else Modifier.fillMaxWidth())
                    .semantics { this.selected = selected },
            colors =
                ButtonDefaults.textButtonColors(
                    backgroundColor = if (selected) BossTheme.colors.raised else Color.Transparent,
                    contentColor = BossTheme.colors.textPrimary,
                ),
        ) {
            Row(
                modifier = if (compact) Modifier else Modifier.fillMaxWidth().padding(horizontal = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    Icons.Outlined.Home,
                    contentDescription = if (compact) "Home" else null,
                    modifier = Modifier.size(18.dp),
                )
                if (!compact) {
                    Spacer(Modifier.width(8.dp))
                    Text("Home")
                }
            }
        }
    }
}
